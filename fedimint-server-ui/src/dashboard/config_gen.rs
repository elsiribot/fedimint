//! Dashboard section for runtime module config generation.
//!
//! Lists all module generations with their lifecycle state and exposes the
//! propose/approve/activate/abort actions backed by the consensus
//! coordinated generation protocol.

use std::collections::BTreeMap;

use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_server_core::dashboard_ui::{DynDashboardApi, ModuleGenerationSummary};
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState};
use maud::{Markup, html};
use serde::Deserialize;
use tracing::warn;

use crate::LOG_UI;

pub const CONFIG_GEN_PROPOSE_ROUTE: &str = "/config-gen/propose";
pub const CONFIG_GEN_APPROVE_ROUTE: &str = "/config-gen/approve";
pub const CONFIG_GEN_ACTIVATE_ROUTE: &str = "/config-gen/activate";
pub const CONFIG_GEN_ABORT_ROUTE: &str = "/config-gen/abort";

#[derive(Deserialize)]
pub struct ProposeForm {
    pub kind: String,
}

#[derive(Deserialize)]
pub struct GenerationForm {
    pub generation_id: u64,
}

pub async fn render(api: &DynDashboardApi) -> Markup {
    let generations = api.module_generations().await;
    let available_kinds = api.available_module_kinds().await;

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Module Generation" }
            div class="card-body" {
                p class="text-muted" {
                    "Add a module to the running federation: one guardian proposes, "
                    "every guardian approves, the distributed key generation runs "
                    "automatically and activation restarts all guardians."
                }

                @if generations.is_empty() {
                    div class="alert alert-secondary" { "No module generations yet" }
                } @else {
                    div class="table-responsive" {
                        table class="table table-sm align-middle" {
                            thead {
                                tr {
                                    th { "#" }
                                    th { "Module" }
                                    th { "Status" }
                                    th { "Detail" }
                                    th { "Actions" }
                                }
                            }
                            tbody {
                                @for generation in &generations {
                                    (render_generation_row(generation))
                                }
                            }
                        }
                    }
                }

                form method="post" action=(CONFIG_GEN_PROPOSE_ROUTE) class="d-flex gap-2 mt-3" {
                    select name="kind" class="form-select w-auto" {
                        @for kind in &available_kinds {
                            option value=(kind) { (kind) }
                        }
                    }
                    button type="submit" class="btn btn-primary" { "Propose New Module" }
                }
            }
        }
    }
}

fn render_generation_row(generation: &ModuleGenerationSummary) -> Markup {
    let badge_class = match generation.state.as_str() {
        "Proposed" => "text-bg-warning",
        "Running DKG" => "text-bg-info",
        "Generated" => "text-bg-primary",
        "Active" => "text-bg-success",
        _ => "text-bg-secondary",
    };

    html! {
        tr {
            td { (generation.generation_id) }
            td { (generation.module_kind) }
            td { span class={ "badge " (badge_class) } { (generation.state) } }
            td { (generation.detail) }
            td {
                div class="d-flex gap-2" {
                    @if generation.can_approve {
                        (action_button(CONFIG_GEN_APPROVE_ROUTE, generation.generation_id, "Approve", "btn-success"))
                    }
                    @if generation.can_activate {
                        (action_button(CONFIG_GEN_ACTIVATE_ROUTE, generation.generation_id, "Activate", "btn-primary"))
                    }
                    @if generation.can_abort {
                        (action_button(CONFIG_GEN_ABORT_ROUTE, generation.generation_id, "Abort", "btn-outline-danger"))
                    }
                }
            }
        }
    }
}

fn action_button(route: &str, generation_id: u64, label: &str, button_class: &str) -> Markup {
    html! {
        form method="post" action=(route) class="m-0" {
            input type="hidden" name="generation_id" value=(generation_id);
            button type="submit" class={ "btn btn-sm " (button_class) } { (label) }
        }
    }
}

pub async fn post_propose(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<ProposeForm>,
) -> impl IntoResponse {
    if let Err(err) = state
        .api
        .propose_module_generation(
            fedimint_core::core::ModuleKind::clone_from_str(&form.kind),
            BTreeMap::new(),
        )
        .await
    {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to propose module generation");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}

pub async fn post_approve(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<GenerationForm>,
) -> impl IntoResponse {
    if let Err(err) = state
        .api
        .approve_module_generation(form.generation_id)
        .await
    {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to approve module generation");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}

pub async fn post_activate(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<GenerationForm>,
) -> impl IntoResponse {
    if let Err(err) = state
        .api
        .activate_module_generation(form.generation_id)
        .await
    {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to activate module generation");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}

pub async fn post_abort(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<GenerationForm>,
) -> impl IntoResponse {
    if let Err(err) = state.api.abort_module_generation(form.generation_id).await {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to abort module generation");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}
