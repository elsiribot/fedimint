#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use db::DbKeyPrefix;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::Context;
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::{Amount, apply, async_trait_maybe_send};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::{UsdtCommonInit, UsdtModuleTypes};
use states::UsdtStateMachine;
use strum::IntoEnumIterator;

pub mod api;
pub mod db;
pub mod states;

#[derive(Debug)]
pub struct UsdtClientModule {
    #[allow(dead_code)]
    cfg: UsdtClientConfig,
    #[allow(dead_code)]
    client_ctx: ClientContext<Self>,
    #[allow(dead_code)]
    db: Database,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct UsdtClientContext {
    pub usdt_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for UsdtClientContext {
    const KIND: Option<ModuleKind> = None;
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for UsdtClientModule {
    type Init = UsdtClientInit;
    type Common = UsdtModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = UsdtClientContext;
    type States = UsdtStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        UsdtClientContext {
            usdt_decoder: self.decoder(),
        }
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        unreachable!()
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        unreachable!()
    }

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        Amount::ZERO
    }
}

#[derive(Debug, Clone)]
pub struct UsdtClientInit;

// TODO: Boilerplate-code
impl ModuleInit for UsdtClientInit {
    type Common = UsdtCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        #[allow(clippy::never_loop)]
        for table in filtered_prefixes {
            match table {}
        }

        Box::new(items.into_iter())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for UsdtClientInit {
    type Module = UsdtClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(UsdtClientModule {
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}
