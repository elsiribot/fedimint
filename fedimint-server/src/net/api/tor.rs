use std::net::SocketAddr;

use anyhow::{Context, anyhow};
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_logging::LOG_NET_API;
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tor_cell::relaycell::msg::Connected;
use tracing::{info, warn};

pub async fn start_tor_api_service(
    task_group: &TaskGroup,
    service_name: &str,
    virtual_port: u16,
    forward_addr: SocketAddr,
) -> anyhow::Result<SafeUrl> {
    let tor_config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(tor_config)
        .await
        .context("Failed to bootstrap Tor client")?
        .isolated_client();

    let mut onion_service_config = OnionServiceConfigBuilder::default();
    onion_service_config.nickname(
        service_name
            .parse()
            .with_context(|| format!("Invalid tor service nickname: {service_name}"))?,
    );

    let onion_service_config = onion_service_config
        .build()
        .context("Failed to build onion service config")?;

    let (service, rend_requests) = tor_client
        .launch_onion_service(onion_service_config)
        .context("Failed to launch onion service")?;

    let onion_address = service
        .onion_address()
        .ok_or_else(|| anyhow!("Onion service did not report an onion address"))?;

    let onion_host = onion_address.display_unredacted().to_string();
    let api_url = SafeUrl::parse(&format!("tor+ws://{onion_host}:{virtual_port}"))
        .context("Failed to build Tor API URL")?;

    info!(target: LOG_NET_API, api_url = %api_url, "Started Tor API onion service");

    let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);
    let task_group_clone = task_group.clone();
    task_group.spawn_cancellable("tor-api", async move {
        let _service = service;
        while let Some(stream_request) = stream_requests.next().await {
            let task_group = task_group_clone.clone();
            task_group.spawn_cancellable_silent("tor-api-stream", async move {
                if let Err(err) = handle_tor_stream_request(stream_request, forward_addr).await {
                    warn!(target: LOG_NET_API, error = %err.fmt_compact_anyhow(), "Failed to forward Tor API stream");
                }
            });
        }
    });

    Ok(api_url)
}

async fn handle_tor_stream_request(
    stream_request: tor_hsservice::StreamRequest,
    forward_addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut tor_stream = stream_request
        .accept(Connected::new_empty())
        .await
        .context("Failed to accept Tor stream")?;

    let mut tcp_stream = TcpStream::connect(forward_addr)
        .await
        .with_context(|| format!("Failed to connect to API listener at {forward_addr}"))?;

    copy_bidirectional(&mut tor_stream, &mut tcp_stream)
        .await
        .context("Failed to proxy Tor stream to websocket API")?;

    Ok(())
}
