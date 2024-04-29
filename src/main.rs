#![feature(allocator_api)]
//! Discover Bluetooth devices and list them.

use bluer::{
    agent::{
        AuthorizeService, ReqError, ReqResult, RequestConfirmation, RequestPasskey, RequestPinCode,
    },
    id::ServiceClass,
    Adapter, AdapterEvent, Address, DeviceEvent, DiscoveryFilter, DiscoveryTransport, Error, Uuid,
};
use core::fmt;
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use futures::{pin_mut, stream::SelectAll, Future, StreamExt};
use mac_address::MacAddress;
use std::{alloc::Global, collections::HashSet, env, pin::Pin, str::FromStr};

#[derive(serde::Deserialize, Clone, Debug)]
struct Settings {
    devices: Vec<MacAddress>,
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
        if device.is_paired().await? {
            device.set_trusted(true).await?;
            device.connect().await?;
            return Ok(());
        }
    }
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    let settings = Figment::new()
        .merge(Yaml::file("config.yaml"))
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

    let adapter = session.default_adapter().await?;
    adapter.set_alias(String::from("car-test1")).await?;
    adapter.set_powered(true).await?;

    adapter.set_discoverable(true).await?;
    adapter.set_discoverable_timeout(0).await?;
    adapter.set_pairable(true).await?;
    adapter.set_pairable_timeout(0).await?;
    adapter.class().await?;

    let events = adapter.events().await?;
    pin_mut!(events);

    reconnect_device(&settings, &adapter).await?;

    loop {
        tokio::select! {
            Some(adapter_event) = events.next() => {
                match adapter_event {
                    AdapterEvent::DeviceAdded(addr) => {
                        println!("Device added: {addr}");
                        // println!("Trusting device...");
                        let device = adapter.device(addr)?;
                        if device.is_paired().await? {
                            device.set_trusted(true).await?;

                        }
                        query_device(&adapter, addr).await?;
                    }
                    _ => (),
                }
                println!();
            }
            else => break
        }
    }
    Ok(())
}
