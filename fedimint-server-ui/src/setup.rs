use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context as _;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::Asset;
use fedimint_server_core::setup_ui::DynSetupApi;
use fedimint_ui_common::assets::WithStaticRoutesExt;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{
    CONNECTIVITY_CHECK_ROUTE, LOGIN_ROUTE, LoginInput, ROOT_ROUTE, UiState,
    connectivity_check_handler, copiable_text, login_form, login_submit_response,
    single_card_layout, single_card_layout_with_version,
};
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use serde::Deserialize;

// Setup route constants
pub const FEDERATION_SETUP_ROUTE: &str = "/federation_setup";
pub const ADD_SETUP_CODE_ROUTE: &str = "/add_setup_code";
pub const RESET_SETUP_CODES_ROUTE: &str = "/reset_setup_codes";
pub const START_DKG_ROUTE: &str = "/start_dkg";
pub const START_FEDERATION_ROUTE: &str = "/start_federation";
pub const RESTORE_GUARDIAN_ROUTE: &str = "/restore_guardian";
const RESTORE_BACKUP_UPLOAD_LIMIT_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(crate) struct SetupInput {
    pub name: String,
    #[serde(default)]
    pub is_lead: bool,
    pub federation_name: String,
    #[serde(default)]
    pub federation_size: String,
    #[serde(default)] // will not be sent if disabled
    pub enable_base_fees: bool,
    // The module instance list, as three index-aligned arrays: one entry per
    // row of the setup form. Browsers submit repeated fields in document order,
    // and every row always submits all three, so entry `i` of each describes
    // the same instance.
    #[serde(default)]
    pub instance_kind: Vec<String>,
    #[serde(default)]
    pub instance_asset: Vec<String>,
    #[serde(default)]
    pub instance_params: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PeerInfoInput {
    pub peer_info: String,
}

fn peer_list_section(
    connected_peers: &[String],
    federation_size: Option<u32>,
    cfg_federation_name: &Option<String>,
    cfg_base_fees_disabled: Option<bool>,
    cfg_module_params: &Option<ServerModuleConfigGenParamsRegistry>,
    error: Option<&str>,
) -> Markup {
    let total_guardians = connected_peers.len() + 1;
    let can_start_dkg = federation_size
        .map(|expected| total_guardians == expected as usize)
        .unwrap_or(false);

    html! {
        div id="peer-list-section" {
            @if let Some(expected) = federation_size {
                p { (format!("{total_guardians} of {expected} guardians connected.")) }
            } @else {
                p { "Add setup code for every other guardian." }
            }

            @if !connected_peers.is_empty() {
                ul class="list-group mb-2" {
                    @for peer in connected_peers {
                        li class="list-group-item" { (peer) }
                    }
                }

                form id="reset-form" method="post" action=(RESET_SETUP_CODES_ROUTE) class="d-none" {}
                div class="text-center mb-4" {
                    button type="button" class="btn btn-link text-danger text-decoration-none p-0" onclick="if(confirm('Are you sure you want to reset all guardians?')){document.getElementById('reset-form').submit();}" {
                        "Reset Guardians"
                    }
                }
            }

            @if can_start_dkg {
                // All guardians connected — show confirm form
                @let has_settings = cfg_federation_name.is_some()
                    || federation_size.is_some()
                    || cfg_base_fees_disabled.is_some()
                    || cfg_module_params.is_some();

                form id="start-dkg-form" hx-post=(START_DKG_ROUTE) hx-target="#peer-list-section" hx-swap="outerHTML" {
                    @if let Some(error) = error {
                        div class="alert alert-danger mb-3" { (error) }
                    }
                    button type="submit" class="btn btn-warning w-100 py-2" { "Confirm" }
                }

                @if has_settings {
                    p class="text-muted mt-3 mb-0" style="font-size: 0.85rem;" {
                        @if let Some(name) = cfg_federation_name {
                            (name) " federation has been configured"
                        } @else {
                            "The federation has been configured"
                        }
                        @if let Some(disabled) = cfg_base_fees_disabled {
                            " with base fees "
                            @if disabled { "disabled" } @else { "enabled" }
                        }
                        @if let Some(module_params) = cfg_module_params {
                            " and modules "
                            (module_params.kinds().iter().map(|m| m.as_str().to_owned()).collect::<Vec<_>>().join(", "))
                        }
                        "."
                    }
                }
            } @else {
                // Still collecting — show add guardian form
                form id="add-setup-code-form" hx-post=(ADD_SETUP_CODE_ROUTE) hx-target="#peer-list-section" hx-swap="outerHTML" {
                    div class="mb-3" {
                        div class="input-group" {
                            input type="text" class="form-control" id="peer_info" name="peer_info"
                                placeholder="Paste Setup Code" required;
                            button type="button" class="btn btn-outline-secondary" onclick="startQrScanner()" title="Scan QR Code" {
                                i class="bi bi-qr-code-scan" {}
                            }
                        }
                    }

                    @if let Some(error) = error {
                        div class="alert alert-danger mb-3" { (error) }
                    }
                    button type="submit" class="btn btn-primary w-100 py-2" { "Add Guardian" }
                }
            }
        }
    }
}

fn setup_error_message(error: &str) -> Markup {
    html! {
        div class="alert alert-danger mb-3" { (error) }
    }
}

fn setup_choice_content(error: Option<&str>) -> Markup {
    html! {
        @if let Some(error) = error {
            (setup_error_message(error))
        }

        div class="d-grid gap-3" {
            a href=(START_FEDERATION_ROUTE) class="btn btn-primary w-100 py-2" {
                "Start new Federation"
            }

            a href=(RESTORE_GUARDIAN_ROUTE) class="btn btn-outline-secondary w-100 py-2" {
                "Restore from backup"
            }
        }
    }
}

fn restore_form_content(error: Option<&str>) -> Markup {
    html! {
        @if let Some(error) = error {
            (setup_error_message(error))
        }

        p class="text-muted" {
            "Upload a guardian backup tar file. The password is only required for older, encrypted backups; leave it blank otherwise."
        }

        form method="post" action=(RESTORE_GUARDIAN_ROUTE) enctype="multipart/form-data" {
            div class="form-group mb-3" {
                input type="password" class="form-control" name="password" placeholder="Guardian Password (only for encrypted backups)";
            }
            div class="form-group mb-3" {
                input type="file" class="form-control" name="backup" accept="application/x-tar,.tar" required;
            }
            button type="submit" class="btn btn-primary w-100 py-2" {
                "Restore Guardian"
            }
        }

        div class="text-center mt-3" {
            a href=(ROOT_ROUTE) class="btn btn-link text-muted text-decoration-none" {
                "Back"
            }
        }
    }
}

fn restore_error_response(error: impl AsRef<str>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Html(
            single_card_layout(
                "Restore Guardian",
                restore_form_content(Some(error.as_ref())),
            )
            .into_string(),
        ),
    )
        .into_response()
}

/// Turn the setup form's three parallel row arrays into a module instance list.
///
/// Instance ids follow row order, so this produces the same shape as the
/// `--module` CLI flag for the same sequence of modules.
///
/// Params for a row are its JSON text (empty means "no params"), with the
/// selected asset written into the kind's declared asset field on top. A row
/// whose kind declares no asset field ignores its asset value entirely — the
/// form keeps a hidden asset `select` in every row to keep the arrays aligned,
/// and a hidden `select` still submits whatever option happens to be selected.
/// Ignoring it here rather than trusting the script to blank it is what keeps a
/// stale selection out of the wrong module's params.
///
/// A row that names no params falls back to the kind's own
/// `default_config_gen_params` rather than to JSON null. Null is only correct
/// for modules whose `Params` is `()`; a module with a real params struct
/// fails to deserialize from it, so defaulting to null would break every
/// such module configured through the form without touching its fields.
fn build_module_params(
    kinds: &[String],
    assets: &[String],
    params: &[String],
    asset_param_fields: &BTreeMap<ModuleKind, String>,
    default_params: &BTreeMap<ModuleKind, serde_json::Value>,
) -> anyhow::Result<ServerModuleConfigGenParamsRegistry> {
    anyhow::ensure!(
        kinds.len() == assets.len() && kinds.len() == params.len(),
        "Malformed module list: {} kinds, {} assets, {} params",
        kinds.len(),
        assets.len(),
        params.len(),
    );

    let mut registry = ServerModuleConfigGenParamsRegistry::default();

    for ((kind_str, asset_str), params_str) in kinds.iter().zip(assets).zip(params) {
        let kind_str = kind_str.trim();
        if kind_str.is_empty() {
            continue;
        }
        let kind = ModuleKind::clone_from_str(kind_str);

        let params_str = params_str.trim();
        let mut value = if params_str.is_empty() {
            default_params.get(&kind).cloned().unwrap_or_default()
        } else {
            serde_json::from_str(params_str)
                .with_context(|| format!("Invalid JSON params for module {kind_str}"))?
        };

        if let Some(field) = asset_param_fields.get(&kind) {
            let asset_str = asset_str.trim();
            if !asset_str.is_empty() {
                let unit: u64 = asset_str
                    .parse()
                    .with_context(|| format!("Invalid asset id {asset_str:?} for {kind_str}"))?;

                if value.is_null() {
                    value = serde_json::Value::Object(serde_json::Map::new());
                }
                let object = value.as_object_mut().with_context(|| {
                    format!("Params for module {kind_str} must be a JSON object to carry an asset")
                })?;
                object.insert(field.clone(), serde_json::json!(unit));
            }
        }

        registry.attach_config_gen_params(kind, value);
    }

    Ok(registry)
}

/// One module-instance row: which kind, which asset it is denominated in (for
/// kinds that take one), and any remaining config-gen params as JSON.
///
/// `selected` prefills the kind; `None` renders the blank row that the "+ Add
/// module" button clones, so the server renders the markup exactly once and the
/// script only copies it.
///
/// Every row submits all three fields, including the ones a given kind does not
/// use, so that the three parallel arrays stay index-aligned on the server. The
/// asset column is hidden rather than removed for the same reason. The server
/// ignores `instance_asset` for kinds that declare no asset field, so a stale
/// hidden selection cannot leak into the wrong module's params.
fn module_row(
    available_modules: &BTreeSet<ModuleKind>,
    available_assets: &[Asset],
    asset_param_fields: &BTreeMap<ModuleKind, String>,
    selected: Option<&ModuleKind>,
) -> Markup {
    let takes_asset = selected.is_some_and(|kind| asset_param_fields.contains_key(kind));

    html! {
        div class="row g-2 align-items-center module-row mb-2" {
            div class="col-12 col-sm" {
                select class="form-select form-select-sm module-kind" name="instance_kind" {
                    @for kind in available_modules {
                        option value=(kind.as_str()) selected[selected == Some(kind)] {
                            (kind.as_str())
                        }
                    }
                }
            }

            div class="col-12 col-sm module-asset-col" style=(if takes_asset { "" } else { "display: none;" }) {
                select class="form-select form-select-sm module-asset" name="instance_asset" {
                    option value="" { "(no asset)" }
                    @for asset in available_assets {
                        option value=(asset.unit.id().to_string()) { (asset.label()) }
                    }
                }
            }

            div class="col-12 col-sm" {
                input type="text" class="form-control form-control-sm module-params"
                    name="instance_params" placeholder="extra params (JSON, optional)";
            }

            div class="col-auto" {
                button type="button" class="btn btn-outline-secondary btn-sm module-remove"
                    aria-label="Remove module" { "\u{00d7}" }
            }
        }
    }
}

fn setup_form_content(
    available_modules: &BTreeSet<ModuleKind>,
    default_modules: &BTreeSet<ModuleKind>,
    available_assets: &[Asset],
    asset_param_fields: &BTreeMap<ModuleKind, String>,
) -> Markup {
    // Only the kind names reach the script; the params field name each maps to
    // stays server-side, since the server is what writes the chosen unit into
    // the params.
    let asset_kinds_json = serde_json::to_string(
        &asset_param_fields
            .keys()
            .map(|kind| (kind.as_str().to_owned(), true))
            .collect::<BTreeMap<_, _>>(),
    )
    .expect("a map of string keys to bools always serializes");

    html! {
        form id="setup-form" hx-post=(ROOT_ROUTE) hx-target="#setup-error" hx-swap="innerHTML" {
            style {
                r#"
                .toggle-content {
                    display: none;
                }

                .toggle-control:checked ~ .toggle-content {
                    display: block;
                }

                #base-fees-warning {
                    display: block;
                }

                .form-check:has(#enable_base_fees:checked) + #base-fees-warning {
                    display: none;
                }

                .accordion-button {
                    background-color: #f8f9fa;
                }

                .accordion-button:not(.collapsed) {
                    background-color: #f8f9fa;
                    box-shadow: none;
                }

                .accordion-button:focus {
                    box-shadow: none;
                }

                #modules-warning {
                    display: none;
                }

                #modules-list:has(.form-check-input:not(:checked)) ~ #modules-warning {
                    display: block;
                }
                "#
            }

            div class="form-group mb-4" {
                input type="text" class="form-control" id="name" name="name" placeholder="Your Guardian Name" required;
            }

            div class="alert alert-warning mb-3" style="font-size: 0.875rem;" {
                "Exactly one guardian must set the global config."
            }

            div class="form-group mb-4" {
                input type="checkbox" class="form-check-input toggle-control" id="is_lead" name="is_lead" value="true";

                label class="form-check-label ms-2" for="is_lead" {
                    "Set the global config"
                }

                div class="toggle-content mt-3" {
                    input type="text" class="form-control" id="federation_name" name="federation_name" placeholder="Federation Name";

                    div class="form-group mt-3" {
                        label class="form-label" for="federation_size" {
                            "Total number of guardians (including you)"
                        }
                        select class="form-select" id="federation_size" name="federation_size" {
                            option value="" selected disabled { "Federation Size" }
                            option value="1" { "1 — Testing" }
                            option value="4" { "4 — Recommended" }
                            option value="5" { "5" }
                            option value="6" { "6" }
                            option value="7" { "7 — Recommended" }
                            option value="8" { "8" }
                            option value="9" { "9" }
                            option value="10" { "10 — Recommended" }
                            option value="11" { "11" }
                            option value="12" { "12" }
                            option value="13" { "13 — Recommended" }
                            option value="14" { "14" }
                            option value="15" { "15" }
                            option value="16" { "16 — Recommended" }
                            option value="17" { "17" }
                            option value="18" { "18" }
                            option value="19" { "19 — Recommended" }
                            option value="20" { "20" }
                        }
                    }

                    div class="form-check mt-3" {
                        input type="checkbox" class="form-check-input" id="enable_base_fees" name="enable_base_fees" checked value="true";

                        label class="form-check-label" for="enable_base_fees" {
                            "Enable base fees for this federation"
                        }
                    }

                    div id="base-fees-warning" class="alert alert-warning mt-2" style="font-size: 0.875rem;" {
                        strong { "Warning: " }
                        "Base fees discourage spam and wasting storage space. The typical fee is only 1-3 sats per transaction, regardless of the value transferred. We recommend enabling the base fee and it cannot be changed later."
                    }

                    div class="accordion mt-3" id="modulesAccordion" {
                        div class="accordion-item" {
                            h2 class="accordion-header" {
                                button class="accordion-button collapsed" type="button"
                                    data-bs-toggle="collapse" data-bs-target="#modulesConfig"
                                    aria-expanded="false" aria-controls="modulesConfig" {
                                    "Advanced: Configure Modules"
                                }
                            }
                            div id="modulesConfig" class="accordion-collapse collapse" data-bs-parent="#modulesAccordion" {
                                div class="accordion-body" {
                                    p class="text-muted" style="font-size: 0.875rem;" {
                                        "One row per module instance. A kind may appear more than once — e.g. two mints, each denominated in a different asset."
                                    }

                                    div id="module-rows" {
                                        @for kind in default_modules {
                                            (module_row(available_modules, available_assets, asset_param_fields, Some(kind)))
                                        }
                                    }

                                    button type="button" class="btn btn-outline-secondary btn-sm mt-2" id="add-module-row" {
                                        "+ Add module"
                                    }

                                    template id="module-row-template" {
                                        (module_row(available_modules, available_assets, asset_param_fields, None))
                                    }

                                    div id="modules-warning" class="alert alert-warning mt-3 mb-0" style="font-size: 0.875rem;" {
                                        "Only modify this if you know what you are doing. The module list cannot be changed after setup."
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div id="setup-error" {}
            button type="submit" class="btn btn-primary w-100 py-2" { "Confirm" }
        }

        // Add/remove module rows, and show the asset dropdown only for kinds
        // that are denominated in one. Purely an input aid: the server
        // re-derives everything from the submitted fields and ignores the asset
        // for kinds that take none, so this script failing to run degrades to a
        // fixed list of rows rather than to a wrong config.
        script {
            (PreEscaped(format!(
                r#"
            (function () {{
                var assetKinds = {asset_kinds};
                var rows = document.getElementById('module-rows');
                var tpl = document.getElementById('module-row-template');
                var addBtn = document.getElementById('add-module-row');
                if (!rows || !tpl || !addBtn) {{ return; }}

                function syncAsset(row) {{
                    var kindEl = row.querySelector('.module-kind');
                    var col = row.querySelector('.module-asset-col');
                    var sel = row.querySelector('.module-asset');
                    if (!kindEl || !col || !sel) {{ return; }}
                    var takes = Object.prototype.hasOwnProperty.call(assetKinds, kindEl.value);
                    col.style.display = takes ? '' : 'none';
                    if (!takes) {{ sel.value = ''; }}
                }}

                rows.addEventListener('change', function (e) {{
                    if (e.target && e.target.classList.contains('module-kind')) {{
                        syncAsset(e.target.closest('.module-row'));
                    }}
                }});

                rows.addEventListener('click', function (e) {{
                    var btn = e.target.closest('.module-remove');
                    if (btn) {{ btn.closest('.module-row').remove(); }}
                }});

                addBtn.addEventListener('click', function () {{
                    var row = tpl.content.firstElementChild.cloneNode(true);
                    rows.appendChild(row);
                    syncAsset(row);
                }});
            }})();
            "#,
                asset_kinds = asset_kinds_json,
            )))
        }
    }
}

// GET handler for the / route (choose setup or restore)
async fn setup_form(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    Html(single_card_layout("Guardian Setup", setup_choice_content(None)).into_string())
        .into_response()
}

// GET handler for starting a new federation
async fn start_federation_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    let available_modules = state.api.available_modules();
    let default_modules = state.api.default_modules();
    let available_assets = state.api.available_assets();
    let asset_param_fields = state.api.asset_param_fields();
    let content = setup_form_content(
        &available_modules,
        &default_modules,
        &available_assets,
        &asset_param_fields,
    );
    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;

    Html(
        single_card_layout_with_version(
            "Guardian Setup",
            content,
            &version,
            version_hash.as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for the /setup route (process the setup form)
async fn setup_submit(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
    Form(input): Form<SetupInput>,
) -> impl IntoResponse {
    // Only use these settings if is_lead is true
    let federation_name = if input.is_lead {
        Some(input.federation_name)
    } else {
        None
    };

    let disable_base_fees = if input.is_lead {
        Some(!input.enable_base_fees)
    } else {
        None
    };

    // The leader's form submits one row per module instance, so the instance
    // list is built directly from it rather than materialized from a set of
    // kinds. Instance ids follow row order, matching the `--module` CLI.
    let module_params = if input.is_lead {
        let default_params: BTreeMap<ModuleKind, serde_json::Value> = state
            .api
            .available_module_params()
            .iter_modules()
            .map(|(_id, kind, params)| (kind.clone(), params.clone()))
            .collect();

        match build_module_params(
            &input.instance_kind,
            &input.instance_asset,
            &input.instance_params,
            &state.api.asset_param_fields(),
            &default_params,
        ) {
            Ok(params) => Some(params),
            Err(e) => {
                return Html(setup_error_message(&e.to_string()).into_string()).into_response();
            }
        }
    } else {
        None
    };

    let federation_size = if input.is_lead {
        let s = input.federation_size.trim();
        if s.is_empty() {
            None
        } else {
            match s.parse::<u32>() {
                Ok(size) => Some(size),
                Err(_) => {
                    return Html(setup_error_message("Invalid federation size").into_string())
                        .into_response();
                }
            }
        }
    } else {
        None
    };

    match state
        .api
        .set_local_parameters(
            input.name,
            federation_name,
            disable_base_fees,
            module_params,
            federation_size,
        )
        .await
    {
        Ok(_) => (
            [("HX-Redirect", FEDERATION_SETUP_ROUTE)],
            Html(String::new()),
        )
            .into_response(),
        Err(e) => Html(setup_error_message(&e.to_string()).into_string()).into_response(),
    }
}

// GET handler for restoring from backup
async fn restore_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    Html(single_card_layout("Restore Guardian", restore_form_content(None)).into_string())
        .into_response()
}

async fn restore_submit(
    State(state): State<UiState<DynSetupApi>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut password = None;
    let mut backup = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(e) => return restore_error_response(format!("Failed to read upload: {e}")),
        };

        match field.name() {
            Some("password") => match field.text().await {
                Ok(value) => password = Some(value),
                Err(e) => return restore_error_response(format!("Failed to read password: {e}")),
            },
            Some("backup") => match field.bytes().await {
                // The setup UI is a local guardian-owner interface. We cap the upload size to
                // catch accidental oversized requests, but treat malicious tar expansion by the
                // uploading user as out of scope: they already control this guardian instance.
                Ok(value) => backup = Some(value.to_vec()),
                Err(e) => return restore_error_response(format!("Failed to read backup: {e}")),
            },
            _ => {}
        }
    }

    // An empty password field means the user left it blank, which is the
    // expected case for current plaintext backups.
    let password = password.filter(|password| !password.is_empty());
    let Some(backup) = backup else {
        return restore_error_response("Missing guardian backup file");
    };

    match state.api.restore_from_backup(password, backup).await {
        Ok(()) => {
            let content = html! {
                div class="alert alert-success mb-3" {
                    "Guardian backup restored. The server is starting consensus."
                }
                div class="text-center mt-4" {
                    div class="spinner-border text-primary" role="status" {
                        span class="visually-hidden" { "Loading..." }
                    }
                    p class="mt-2 text-muted" { "Waiting for dashboard..." }
                }
                div
                    hx-get=(ROOT_ROUTE)
                    hx-trigger="every 2s"
                    hx-swap="none"
                    hx-on--after-request={
                        "if (event.detail.xhr.status === 200) { window.location.href = '" (ROOT_ROUTE) "'; }"
                    }
                    style="display: none;"
                {}
            };
            Html(single_card_layout("Guardian Restored", content).into_string()).into_response()
        }
        // Render the full error chain so the underlying cause (e.g. an
        // incorrect password for an encrypted backup) is surfaced rather than
        // just the outermost "Reading restored config" context.
        Err(e) => restore_error_response(format!("{e:#}")),
    }
}

// GET handler for the /login route (display the login form)
async fn login_form_handler(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;
    Html(
        single_card_layout_with_version(
            "Enter Password",
            login_form(None),
            &version,
            version_hash.as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for the /login route (authenticate and set session cookie).
// Only mounted when the guardian has a password configured, so `auth()` is
// always `Some` here.
async fn login_submit(
    State(state): State<UiState<DynSetupApi>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    login_submit_response(
        state
            .api
            .auth_ui()
            .expect("login route is mounted only when auth is configured"),
        state.auth_cookie_name,
        state.auth_cookie_value,
        jar,
        input,
    )
}

// GET handler for the /federation-setup route (main federation management page)
async fn federation_setup(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let our_connection_info = state
        .api
        .setup_code()
        .await
        .expect("Successful authentication ensures that the local parameters have been set");

    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;
    let connected_peers = state.api.connected_peers().await;
    let federation_size = state.api.federation_size().await;
    let cfg_federation_name = state.api.cfg_federation_name().await;
    let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
    let cfg_module_params = state.api.cfg_module_params().await;

    let content = html! {
        p { "Share this with your fellow guardians." }

        @let qr_svg = QrCode::new(&our_connection_info)
            .expect("Failed to generate QR code")
            .render::<qrcode::render::svg::Color>()
            .build();

        div class="text-center mb-3" {
            div class="border rounded p-2 bg-white d-inline-block" style="width: 250px; max-width: 100%;" {
                div style="width: 100%; height: auto; overflow: hidden;" {
                    (PreEscaped(format!(r#"<div style="width: 100%; height: auto;">{}</div>"#,
                        qr_svg.replace("width=", "data-width=")
                              .replace("height=", "data-height=")
                              .replace("<svg", r#"<svg style="width: 100%; height: auto; display: block;""#))))
                }
            }
        }

        div class="mb-4" {
            (copiable_text(&our_connection_info))
        }

        (peer_list_section(&connected_peers, federation_size, &cfg_federation_name, cfg_base_fees_disabled, &cfg_module_params, None))

        // QR Scanner Modal
        div class="modal fade" id="qrScannerModal" tabindex="-1" aria-labelledby="qrScannerModalLabel" aria-hidden="true" {
            div class="modal-dialog modal-dialog-centered" {
                div class="modal-content" {
                    div class="modal-header" {
                        h5 class="modal-title" id="qrScannerModalLabel" { "Scan Setup Code" }
                        button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" {}
                    }
                    div class="modal-body" {
                        div id="qr-reader" style="width: 100%;" {}
                        div id="qr-reader-error" class="alert alert-danger mt-3 d-none" {}
                    }
                    div class="modal-footer" {
                        button type="button" class="btn btn-secondary" data-bs-dismiss="modal" { "Cancel" }
                    }
                }
            }
        }

        script src="/assets/html5-qrcode.min.js" {}

        // QR Scanner JavaScript
        script {
            (PreEscaped(r#"
            var html5QrCode = null;
            var qrScannerModal = null;

            function startQrScanner() {
                // Check for Flutter override hook
                if (typeof window.fedimintQrScannerOverride === 'function') {
                    window.fedimintQrScannerOverride(function(result) {
                        if (result) {
                            document.getElementById('peer_info').value = result;
                        }
                    });
                    return;
                }

                var modalEl = document.getElementById('qrScannerModal');
                qrScannerModal = new bootstrap.Modal(modalEl);

                // Reset error message
                var errorEl = document.getElementById('qr-reader-error');
                errorEl.classList.add('d-none');
                errorEl.textContent = '';

                qrScannerModal.show();

                // Wait for modal to be shown before starting camera
                modalEl.addEventListener('shown.bs.modal', function onShown() {
                    modalEl.removeEventListener('shown.bs.modal', onShown);
                    initializeScanner();
                });

                // Clean up when modal is hidden
                modalEl.addEventListener('hidden.bs.modal', function onHidden() {
                    modalEl.removeEventListener('hidden.bs.modal', onHidden);
                    stopQrScanner();
                });
            }

            function initializeScanner() {
                html5QrCode = new Html5Qrcode("qr-reader");

                var config = {
                    fps: 10,
                    qrbox: { width: 250, height: 250 },
                    aspectRatio: 1.0
                };

                html5QrCode.start(
                    { facingMode: "environment" },
                    config,
                    function(decodedText, decodedResult) {
                        // Success - populate input and close modal
                        document.getElementById('peer_info').value = decodedText;
                        qrScannerModal.hide();
                    },
                    function(errorMessage) {
                        // Ignore scan errors (happens constantly while searching)
                    }
                ).catch(function(err) {
                    var errorEl = document.getElementById('qr-reader-error');
                    errorEl.textContent = 'Unable to access camera: ' + err;
                    errorEl.classList.remove('d-none');
                });
            }

            function stopQrScanner() {
                if (html5QrCode && html5QrCode.isScanning) {
                    html5QrCode.stop().catch(function(err) {
                        console.error('Error stopping scanner:', err);
                    });
                }
            }
            "#))
        }
    };

    Html(
        single_card_layout_with_version(
            "Federation Setup",
            content,
            &version,
            version_hash.as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for adding peer connection info
async fn post_add_setup_code(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
    Form(input): Form<PeerInfoInput>,
) -> impl IntoResponse {
    let error = state.api.add_peer_setup_code(input.peer_info).await.err();

    let connected_peers = state.api.connected_peers().await;
    let federation_size = state.api.federation_size().await;
    let cfg_federation_name = state.api.cfg_federation_name().await;
    let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
    let cfg_module_params = state.api.cfg_module_params().await;

    Html(
        peer_list_section(
            &connected_peers,
            federation_size,
            &cfg_federation_name,
            cfg_base_fees_disabled,
            &cfg_module_params,
            error.as_ref().map(|e| e.to_string()).as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for starting the DKG process
async fn post_start_dkg(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let our_connection_info = state.api.setup_code().await;
    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;

    match state.api.start_dkg().await {
        Ok(()) => {
            let content = html! {
                @if let Some(ref info) = our_connection_info {
                    p { "Share with guardians who still need it." }
                    div class="mb-4" {
                        (copiable_text(info))
                    }
                }

                div class="alert alert-info mb-3" {
                    "All guardians need to confirm their settings. Once completed you will be redirected to the Dashboard."
                }

                // Poll until the dashboard is ready, then redirect
                div
                    hx-get=(ROOT_ROUTE)
                    hx-trigger="every 2s"
                    hx-swap="none"
                    hx-on--after-request={
                        "if (event.detail.xhr.status === 200) { window.location.href = '" (ROOT_ROUTE) "'; }"
                    }
                    style="display: none;"
                {}

                div class="text-center mt-4" {
                    div class="spinner-border text-primary" role="status" {
                        span class="visually-hidden" { "Loading..." }
                    }
                    p class="mt-2 text-muted" { "Waiting for federation setup to complete..." }
                }
            };

            (
                [("HX-Retarget", "body"), ("HX-Reswap", "innerHTML")],
                Html(
                    single_card_layout_with_version(
                        "DKG Started",
                        content,
                        &version,
                        version_hash.as_deref(),
                    )
                    .into_string(),
                ),
            )
                .into_response()
        }
        Err(e) => {
            let connected_peers = state.api.connected_peers().await;
            let federation_size = state.api.federation_size().await;
            let cfg_federation_name = state.api.cfg_federation_name().await;
            let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
            let cfg_module_params = state.api.cfg_module_params().await;

            Html(
                peer_list_section(
                    &connected_peers,
                    federation_size,
                    &cfg_federation_name,
                    cfg_base_fees_disabled,
                    &cfg_module_params,
                    Some(&e.to_string()),
                )
                .into_string(),
            )
            .into_response()
        }
    }
}

// POST handler for resetting peer connection info
async fn post_reset_setup_codes(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    state.api.reset_setup_codes().await;

    Redirect::to(FEDERATION_SETUP_ROUTE).into_response()
}

pub fn router(api: DynSetupApi) -> Router {
    let requires_auth = api.auth_ui().is_some();

    let mut router = Router::new()
        .route(ROOT_ROUTE, get(setup_form).post(setup_submit))
        .route(START_FEDERATION_ROUTE, get(start_federation_form))
        .route(
            RESTORE_GUARDIAN_ROUTE,
            get(restore_form)
                .post(restore_submit)
                .layer(DefaultBodyLimit::max(RESTORE_BACKUP_UPLOAD_LIMIT_BYTES)),
        )
        .route(FEDERATION_SETUP_ROUTE, get(federation_setup))
        .route(ADD_SETUP_CODE_ROUTE, post(post_add_setup_code))
        .route(RESET_SETUP_CODES_ROUTE, post(post_reset_setup_codes))
        .route(START_DKG_ROUTE, post(post_start_dkg))
        .route(
            CONNECTIVITY_CHECK_ROUTE,
            get(connectivity_check_handler::<DynSetupApi>),
        );

    if requires_auth {
        router = router.route(LOGIN_ROUTE, get(login_form_handler).post(login_submit));
    }

    router
        .with_static_routes()
        .with_state(UiState::new(api, requires_auth))
}

#[cfg(test)]
mod tests {
    use fedimint_core::module::AmountUnit;

    use super::*;

    fn mintv2() -> ModuleKind {
        ModuleKind::clone_from_str("mintv2")
    }

    fn asset_fields() -> BTreeMap<ModuleKind, String> {
        BTreeMap::from([(mintv2(), "amount_unit".to_owned())])
    }

    /// Stands in for what `default_config_gen_params` produces per kind:
    /// `mintv2` has a real params struct, `walletv2`'s `Params` is `()` and so
    /// serializes to null.
    fn defaults() -> BTreeMap<ModuleKind, serde_json::Value> {
        BTreeMap::from([
            (mintv2(), serde_json::json!({"amount_unit": 0})),
            (
                ModuleKind::clone_from_str("walletv2"),
                serde_json::Value::Null,
            ),
        ])
    }

    fn rows(specs: &[(&str, &str, &str)]) -> (Vec<String>, Vec<String>, Vec<String>) {
        (
            specs.iter().map(|(k, _, _)| (*k).to_owned()).collect(),
            specs.iter().map(|(_, a, _)| (*a).to_owned()).collect(),
            specs.iter().map(|(_, _, p)| (*p).to_owned()).collect(),
        )
    }

    /// The whole point of the change: two instances of one kind, each
    /// denominated in a different asset, with ids following row order.
    #[test]
    fn builds_two_instances_of_one_kind_with_distinct_assets() {
        let (k, a, p) = rows(&[
            ("walletv2", "", ""),
            ("mintv2", "0", ""),
            ("mintv2", "1", ""),
        ]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");

        let instances: Vec<(u16, String, serde_json::Value)> = registry
            .iter_modules()
            .map(|(id, kind, params)| (id, kind.to_string(), params.clone()))
            .collect();

        assert_eq!(
            instances,
            vec![
                (0, "walletv2".to_owned(), serde_json::Value::Null),
                (
                    1,
                    "mintv2".to_owned(),
                    serde_json::json!({"amount_unit": 0})
                ),
                (
                    2,
                    "mintv2".to_owned(),
                    serde_json::json!({"amount_unit": 1})
                ),
            ]
        );
    }

    /// A paramless row must produce JSON `null`, not `{}`.
    ///
    /// A module whose `Params` is `()` deserializes from null and *fails* on an
    /// empty object, so getting this wrong breaks every paramless module at
    /// config gen rather than in this function.
    #[test]
    fn paramless_row_is_null_not_empty_object() {
        let (k, a, p) = rows(&[("walletv2", "", "")]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");
        let params = registry
            .iter_modules()
            .next()
            .expect("one instance")
            .2
            .clone();

        assert_eq!(params, serde_json::Value::Null);
        assert_ne!(params, serde_json::json!({}));
    }

    /// A row that touches nothing gets the kind's own default params, not
    /// JSON null.
    ///
    /// Null only deserializes into a `Params` of `()`. A module with a real
    /// params struct — `mintv2` — fails on it, so defaulting to null would
    /// break config generation for every such module added through the form
    /// and left at its defaults, which is the most ordinary thing an operator
    /// can do.
    #[test]
    fn untouched_row_gets_the_kinds_default_params() {
        let (k, a, p) = rows(&[("mintv2", "", "")]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");
        let params = registry
            .iter_modules()
            .next()
            .expect("one instance")
            .2
            .clone();

        assert_eq!(params, serde_json::json!({"amount_unit": 0}));
        assert_ne!(params, serde_json::Value::Null);
    }

    /// A kind that declares no asset field must ignore whatever the asset
    /// select submitted.
    ///
    /// The form keeps a hidden asset `select` in every row so the three arrays
    /// stay index-aligned, and a hidden select still submits its current option.
    /// Without this rule a stale selection would be written into a module that
    /// has no such param, and config gen would reject it.
    #[test]
    fn asset_is_ignored_for_kinds_without_an_asset_field() {
        let (k, a, p) = rows(&[("walletv2", "1", "")]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");
        let params = registry
            .iter_modules()
            .next()
            .expect("one instance")
            .2
            .clone();

        assert_eq!(params, serde_json::Value::Null);
    }

    /// The asset selection merges into hand-written params rather than
    /// replacing them.
    #[test]
    fn asset_merges_into_explicit_params() {
        let (k, a, p) = rows(&[("mintv2", "1", r#"{"other": 7}"#)]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");
        let params = registry
            .iter_modules()
            .next()
            .expect("one instance")
            .2
            .clone();

        assert_eq!(params, serde_json::json!({"other": 7, "amount_unit": 1}));
    }

    /// Rows with no asset chosen keep their params untouched, so a kind that
    /// takes an asset can still be configured entirely by hand.
    #[test]
    fn empty_asset_leaves_params_alone() {
        let (k, a, p) = rows(&[("mintv2", "", r#"{"amount_unit": 3}"#)]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");
        let params = registry
            .iter_modules()
            .next()
            .expect("one instance")
            .2
            .clone();

        assert_eq!(params, serde_json::json!({"amount_unit": 3}));
    }

    /// Misaligned arrays must be rejected rather than silently zipped short.
    ///
    /// `zip` truncates to the shortest input, so without the explicit length
    /// check a dropped field would quietly discard trailing instances.
    #[test]
    fn misaligned_rows_are_rejected() {
        let err = build_module_params(
            &["mintv2".to_owned(), "walletv2".to_owned()],
            &["0".to_owned()],
            &[String::new(), String::new()],
            &asset_fields(),
            &defaults(),
        )
        .expect_err("misaligned arrays must error");

        assert!(err.to_string().contains("Malformed module list"), "{err}");
    }

    #[test]
    fn invalid_params_json_is_rejected() {
        let (k, a, p) = rows(&[("mintv2", "", "{not json}")]);

        let err = build_module_params(&k, &a, &p, &asset_fields(), &defaults())
            .expect_err("malformed JSON must error");

        assert!(err.to_string().contains("mintv2"), "{err}");
    }

    /// Blank rows (a kind cleared to empty) are skipped, not turned into an
    /// instance with an empty kind.
    #[test]
    fn blank_rows_are_skipped() {
        let (k, a, p) = rows(&[("", "", ""), ("walletv2", "", "")]);

        let registry =
            build_module_params(&k, &a, &p, &asset_fields(), &defaults()).expect("valid rows");

        assert_eq!(registry.iter_modules().count(), 1);
    }

    /// The asset dropdown is rendered for kinds that declare an asset field,
    /// and the script is told which kinds those are.
    #[test]
    fn form_offers_declared_assets_for_asset_taking_kinds() {
        let content = setup_form_content(
            &BTreeSet::from([mintv2()]),
            &BTreeSet::from([mintv2()]),
            &[Asset::new(AmountUnit::new_custom(1), "USDT")],
            &asset_fields(),
        )
        .into_string();

        assert!(content.contains("USDT (unit 1)"), "asset option missing");
        assert!(content.contains(r#"name="instance_asset""#));
        assert!(content.contains(r#"name="instance_kind""#));
        assert!(
            content.contains(r#"{"mintv2":true}"#),
            "script must know which kinds take an asset"
        );
    }

    #[test]
    fn setup_form_targets_error_container() {
        let content = setup_form_content(&BTreeSet::new(), &BTreeSet::new(), &[], &BTreeMap::new())
            .into_string();

        assert!(content.contains(r##"hx-target="#setup-error""##));
        assert!(content.contains(r#"<div id="setup-error"></div>"#));
    }

    #[test]
    fn setup_error_message_is_partial() {
        let content = setup_error_message("Invalid federation size").into_string();

        assert!(content.contains("Invalid federation size"));
        assert!(!content.contains("setup-form"));
    }

    #[test]
    fn setup_choice_has_start_and_restore_options() {
        let content = setup_choice_content(None).into_string();

        assert!(content.contains("Start new Federation"));
        assert!(content.contains("Restore from backup"));
        assert!(!content.contains("multipart/form-data"));
    }

    #[test]
    fn restore_form_has_upload_fields() {
        let content = restore_form_content(None).into_string();

        assert!(content.contains("multipart/form-data"));
        assert!(content.contains("Guardian Password"));
        assert!(content.contains("Restore Guardian"));
    }
}
