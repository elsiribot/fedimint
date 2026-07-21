//! Dashboard section for runtime module config generation.
//!
//! Lists all module generations with their lifecycle state and exposes the
//! propose/approve/activate/abort actions backed by the consensus
//! coordinated generation protocol.

use std::collections::BTreeMap;

use axum::extract::{Form, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_server_core::ConfigGenParamType;
use fedimint_server_core::dashboard_ui::{DynDashboardApi, ModuleGenerationSummary};
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState, dashboard_layout};
use maud::{Markup, html};
use serde::Deserialize;
use tracing::warn;

use crate::LOG_UI;

pub const CONFIG_GEN_PROPOSE_ROUTE: &str = "/config-gen/propose";
pub const CONFIG_GEN_PROPOSE_FORM_ROUTE: &str = "/config-gen/propose-form";
pub const CONFIG_GEN_APPROVE_ROUTE: &str = "/config-gen/approve";
pub const CONFIG_GEN_ACTIVATE_ROUTE: &str = "/config-gen/activate";
pub const CONFIG_GEN_ABORT_ROUTE: &str = "/config-gen/abort";

#[derive(Deserialize)]
pub struct ProposeFormQuery {
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
            td {
                (generation.detail)
                @if !generation.params.is_empty() {
                    br;
                    small class="text-muted" {
                        @for (name, value) in &generation.params {
                            (name) "=" (value) " "
                        }
                    }
                }
            }
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

/// Renders the standalone param-entry page for proposing a generation of a
/// module kind that declares config-gen params.
pub async fn get_propose_form(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Query(query): Query<ProposeFormQuery>,
) -> impl IntoResponse {
    let kind = fedimint_core::core::ModuleKind::clone_from_str(&query.kind);
    let docs = state.api.module_param_docs(kind.clone()).await;
    let assets = state.api.assets().await;

    let content = html! {
        div class="row gy-4" {
            div class="col-12" {
                div class="card" {
                    div class="card-header dashboard-header" { "Propose " (kind) " Module" }
                    div class="card-body" {
                        form method="post" action=(CONFIG_GEN_PROPOSE_ROUTE) {
                            input type="hidden" name="kind" value=(kind);
                            @for doc in &docs {
                                div class="mb-3" {
                                    label class="form-label" { (doc.name) }
                                    @match doc.param_type {
                                        ConfigGenParamType::Asset => {
                                            select name={ "param_" (doc.name) } class="form-select" {
                                                option value="" { "bitcoin (default)" }
                                                @for asset in &assets {
                                                    option value=(asset.id) {
                                                        (asset.ticker) " — " (asset.name)
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            input type="text" name={ "param_" (doc.name) }
                                                class="form-control" required[doc.required];
                                        }
                                    }
                                    div class="form-text" { (doc.description) }
                                }
                            }
                            button type="submit" class="btn btn-primary" { "Propose" }
                            a href=(ROOT_ROUTE) class="btn btn-outline-secondary ms-2" { "Cancel" }
                        }
                    }
                }
            }
        }
    };

    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;

    Html(dashboard_layout(content, &version, version_hash.as_deref()).into_string()).into_response()
}

/// Handles the propose form submission. If the module kind declares config
/// generation params and the request did not carry any `param_*` fields
/// (i.e. it came from the one-click "Propose New Module" form), redirect to
/// the param entry page instead of proposing immediately.
pub async fn post_propose(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<BTreeMap<String, String>>,
) -> impl IntoResponse {
    let Some(kind) = form.get("kind").cloned() else {
        return Redirect::to(ROOT_ROUTE).into_response();
    };
    let kind = fedimint_core::core::ModuleKind::clone_from_str(&kind);

    let has_param_fields = form.keys().any(|key| key.starts_with("param_"));
    let docs = state.api.module_param_docs(kind.clone()).await;

    // Kind has params but the one-click form was used: show the param form.
    if !docs.is_empty() && !has_param_fields {
        return Redirect::to(&format!("{CONFIG_GEN_PROPOSE_FORM_ROUTE}?kind={kind}"))
            .into_response();
    }

    let params: BTreeMap<String, String> = form
        .into_iter()
        .filter_map(|(key, value)| {
            let name = key.strip_prefix("param_")?;
            (!value.is_empty()).then(|| (name.to_string(), value))
        })
        .collect();

    if let Err(err) = state.api.propose_module_generation(kind, params).await {
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
