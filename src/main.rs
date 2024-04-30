#![feature(allocator_api)]
//! Discover Bluetooth devices and list them.

use bluer::{
    agent::{
        AuthorizeService, ReqError, ReqResult, RequestConfirmation, RequestPasskey, RequestPinCode,
    },
    id::ServiceClass,
    Adapter, AdapterEvent, Address, DeviceEvent, DiscoveryFilter, DiscoveryTransport, Uuid,
};
use clap::{arg, Parser};
use core::fmt;
use figment::{
    providers::{Format, Serialized, Yaml},
    Figment,
};
use futures::{pin_mut, stream::SelectAll, Future, StreamExt};
use mac_address::MacAddress;
use serde::de::MapAccess;
use std::{
    alloc::Global,
    collections::HashSet,
    env,
    pin::Pin,
    process::{exit, ExitCode},
    str::FromStr,
    sync::Arc,
};
use tokio::signal::ctrl_c;

#[derive(Debug)]
struct Error {
    message: String,
}

#[derive(serde::Deserialize, serde::Serialize, Parser, Clone, Debug)]
#[command(version, about, long_about=None)]
struct Settings {
    #[arg(long)]
    name: Option<String>,
    devices: Vec<MacAddress>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            name: None,
            devices: Vec::new(),
        }
    }
}

impl From<bluer::Error> for Error {
    fn from(e: bluer::Error) -> Self {
        Self {
            message: format!("{}", e),
        }
    }
}

async fn query_device(adapter: &Adapter, addr: Address) -> bluer::Result<()> {
    let device = adapter.device(addr)?;
    println!("    Address type:       {}", device.address_type().await?);
    println!("    Name:               {:?}", device.name().await?);
    println!("    Icon:               {:?}", device.icon().await?);
    println!("    Class:              {:?}", device.class().await?);
    println!(
        "    UUIDs:              {:?}",
        device.uuids().await?.unwrap_or_default()
    );
    println!("    Paired:             {:?}", device.is_paired().await?);
    println!("    Connected:          {:?}", device.is_connected().await?);
    println!("    Trusted:            {:?}", device.is_trusted().await?);
    println!("    Modalias:           {:?}", device.modalias().await?);
    println!("    RSSI:               {:?}", device.rssi().await?);
    println!("    TX power:           {:?}", device.tx_power().await?);
    println!(
        "    Manufacturer data:  {:?}",
        device.manufacturer_data().await?
    );
    println!("    Service data:       {:?}", device.service_data().await?);
    Ok(())
}

async fn reconnect_device(settings: &Settings, adapter: &Adapter) -> bluer::Result<()> {
    for saved_device in settings.devices.iter() {
        // Parse string to Address
        let addr = Address(saved_device.bytes());
        let device = adapter.device(addr)?;
        match device.is_paired().await {
            Ok(_) => {
                println!("Device found: {}", saved_device);
                // device.set_trusted(true).await?;
                println!("Device connecting...");
                device.connect().await?;
                return Ok(());
            }
            Err(_) => {
                println!("Device not found: {}", saved_device);
                let mut settings = settings.clone();
                settings.devices.retain(|d| d != saved_device);
                save_settings(&settings).await?;
            }
        }
    }
    println!("No devices found in auto-connect list");
    // Err(Error::)
    Ok(())
}

async fn authorize_service(auth: AuthorizeService) -> Result<(), ReqError> {
    let service: ServiceClass = auth.service.try_into().unwrap();

    // let av = Uuid::from(ServiceClass::Av);
    println!("Authorize service: {:?}", service);
    match service {
        ServiceClass::AdvancedAudio | ServiceClass::AudioSink | ServiceClass::Headset => {
            println!("Authorize Audio services");
            Ok(())
        }
        _ => {
            println!("Rejecting service: {}", service);
            Err(ReqError::Rejected)
        }
    }
    // Ok(())
}

async fn confirm(req: RequestConfirmation) -> Result<(), ReqError> {
    println!("Confirm: {:?}", req);
    Ok(())
}

fn config_exists() -> bool {
    dirs::config_dir().map_or(false, |dir| dir.join("bluer/config.yaml").exists())
}

async fn save_settings(settings: &Settings) -> bluer::Result<()> {
    let yaml = serde_yaml::to_string(settings).unwrap();
    std::fs::write(dirs::config_dir().unwrap().join("bluer/config.yaml"), yaml)?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    if !config_exists() {
        std::fs::create_dir_all(dirs::config_dir().unwrap().join("bluer")).map_err(|e| Error {
            message: format!("Failed to create config directory: {}", e),
        })?;
        save_settings(&Settings::default()).await?;
    }
    println!(
        "{:?}",
        dirs::config_dir().unwrap().join("bluer/config.yaml")
    );
    let mut settings = Figment::new()
        .merge(Yaml::file(
            dirs::config_dir().unwrap().join("bluer/config.yaml"),
        ))
        .admerge(Serialized::defaults(Settings::parse()))
        // .merge(Yaml::file("config.yaml"))
        .extract::<Settings>()
        .unwrap();

    env_logger::init();
    let session = bluer::Session::new().await?;
    let _agent = session
        .register_agent(bluer::agent::Agent {
            request_default: true,
            request_pin_code: None,
            display_pin_code: None,
            request_passkey: None,
            display_passkey: None,
            request_confirmation: Some(Box::new(|req| Box::pin(confirm(req)))),
            request_authorization: None,
            authorize_service: Some(Box::new(|auth| Box::pin(authorize_service(auth)))),
            _non_exhaustive: (),
        })
        .await?;

    let adapter = Arc::new(session.default_adapter().await.map_err(|e| Error {
        message: format!("Failed to get default adapter: {}", e),
    })?);
    if let Some(name) = settings.name.clone() {
        adapter.set_alias(name).await?;
    }
    // adapter.set_alias(String::from("car-test1")).await?;
    adapter.set_powered(true).await?;

    adapter.set_discoverable(true).await?;
    adapter.set_discoverable_timeout(0).await?;
    adapter.set_pairable(true).await?;
    adapter.set_pairable_timeout(0).await?;

    let events = adapter.events().await?;
    pin_mut!(events);

    reconnect_device(&settings, &adapter).await?;

    let adapter_ref = adapter.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        adapter_ref.set_powered(false).await.unwrap();
        exit(0)
    });

    let mut connected_device: Option<Address> = None;

    loop {
        tokio::select! {
            Some(adapter_event) = events.next() => {
                match adapter_event {
                    AdapterEvent::DeviceAdded(addr) => {
                        let device = adapter.device(addr)?;
                        query_device(&adapter, addr).await?;
                        println!("Device detected: {} {:?}", addr, device.name().await?);
                        // println!("Trusting device...");
                        // if settings.devices.contains(&MacAddress::new(addr.0)) && !device.is_connected().await? {
                        //     println!("Device is in auto-connect list, attempting to connect...");
                        //     device.connect().await?;
                        //     println!("Device connected");
                        //     connected_device = Some(addr);

                        // }
                        if device.is_paired().await? {
                            // query_device(&adapter, addr).await?;
                            // println!("Device is paired");
                            device.set_trusted(true).await?;
                            // println!("Device trusted, connecting...");
                            if !settings.devices.contains(&MacAddress::new(addr.0)) {
                                println!("Device paired, Adding device to auto-connect...");
                                settings.devices.push(MacAddress::new(addr.0));
                                save_settings(&settings).await?;
                                println!("Device added to auto-connect list");
                                device.connect().await?;
                                println!("Device connected");
                            }
                        }
                    },
                    AdapterEvent::DeviceRemoved(addr) => {
                        println!("Device removed: {}", addr);
                        if let Some(device_addr) = connected_device {
                            if device_addr == addr {
                                connected_device = None;
                                adapter.set_discoverable(true).await?;
                                adapter.set_discoverable_timeout(0).await?;
                                adapter.set_pairable(true).await?;
                                adapter.set_pairable_timeout(0).await?;
                            }
                        }
                    },
                    _ => (),
                }
            }
            else => break
        }
    }
    Ok(())
}
