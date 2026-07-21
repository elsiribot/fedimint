//! Dashboard section for the guardian asset registry.

use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState};
use maud::{Markup, html};
use serde::Deserialize;
use tracing::warn;

use crate::LOG_UI;

pub const ASSETS_REGISTER_ROUTE: &str = "/assets/register";

#[derive(Deserialize)]
pub struct RegisterAssetForm {
    pub name: String,
    pub ticker: String,
}

pub async fn render(api: &DynDashboardApi) -> Markup {
    let assets = api.assets().await;

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Asset Registry" }
            div class="card-body" {
                p class="text-muted" {
                    "Human-readable names for custom amount units. Id 0 is "
                    "always bitcoin. Any guardian can register an asset; it "
                    "takes effect once the consensus item is processed."
                }

                @if assets.is_empty() {
                    div class="alert alert-secondary" { "No assets registered yet" }
                } @else {
                    div class="table-responsive" {
                        table class="table table-sm align-middle" {
                            thead { tr { th { "Id" } th { "Name" } th { "Ticker" } } }
                            tbody {
                                @for asset in &assets {
                                    tr {
                                        td { (asset.id) }
                                        td { (asset.name) }
                                        td { (asset.ticker) }
                                    }
                                }
                            }
                        }
                    }
                }

                form method="post" action=(ASSETS_REGISTER_ROUTE) class="d-flex gap-2 mt-3" {
                    input type="text" name="name" class="form-control w-auto" placeholder="Name" required;
                    input type="text" name="ticker" class="form-control w-auto" placeholder="Ticker" required;
                    button type="submit" class="btn btn-primary" { "Register Asset" }
                }
            }
        }
    }
}

pub async fn post_register(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<RegisterAssetForm>,
) -> impl IntoResponse {
    if let Err(err) = state.api.register_asset(form.name, form.ticker).await {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to register asset");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}
