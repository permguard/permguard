// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Only the catalog facade writes the catalog (WP-7.3a): the inventory of
//! `permguard_conformance::catalog_writers` finds no write outside it, and a seeded one is found
//! however it is called.

use std::path::Path;

use permguard_conformance::catalog_writers::{check, scan};

#[test]
fn only_the_catalog_facade_writes_the_catalog() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let found = check(&root);
    assert!(
        found.is_empty(),
        "the catalog written outside its facade, which runs every change in the WP-3.6 \
         transaction; go through `CatalogFacade`:\n{}",
        found
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A method call, a path call, a function pointer and a call inside a macro are writes all the
/// same; test code, a definition and a local function named like the operation are not.
#[test]
fn a_seeded_write_is_found_however_it_is_called() {
    let seeded = r#"
        fn direct(catalog: &dyn Catalog) {
            catalog.create_zone("billing");
        }

        fn qualified(catalog: &FileCatalog) {
            Catalog::rename_ledger_with(catalog, &zone, &ledger, "x", &Write::default());
        }

        fn pointer(catalog: &FileCatalog) {
            let delete = FileCatalog::delete_zone;
            delete(catalog, &zone);
        }

        fn qualified_self(catalog: &FileCatalog) {
            <FileCatalog as Catalog>::create_ledger_with(catalog, &zone, "x", &Write::default());
        }

        fn bare_self(catalog: &FileCatalog) {
            <FileCatalog>::delete_zone(catalog, &zone);
        }

        fn quiet(catalog: &FileCatalog) {
            debug_assert!(catalog.delete_ledger(&zone, &ledger).is_ok());
        }

        impl Catalog for FileCatalog {
            fn create_zone_with(&self, name: &str, write: &Write<'_>) -> Result<Zone, CatalogError> {
                self.store(name)
            }
        }

        fn reads(catalog: &dyn Catalog) {
            catalog.get_zone(&zone);
            catalog.list_ledgers(&zone);
        }

        fn routes() -> Router {
            Router::new().route("/v1/zones", get(list_zones).post(create_zone))
        }

        #[cfg(test)]
        mod tests {
            fn seeds(catalog: &dyn Catalog) {
                catalog.create_zone("billing");
            }
        }
    "#;
    let found: Vec<(usize, String)> = scan("seeded.rs", seeded)
        .into_iter()
        .map(|write| (write.line, write.method))
        .collect();
    assert_eq!(
        found,
        vec![
            (3, "create_zone".to_owned()),
            (7, "rename_ledger_with".to_owned()),
            (11, "delete_zone".to_owned()),
            (16, "create_ledger_with".to_owned()),
            (20, "delete_zone".to_owned()),
            (24, "delete_ledger".to_owned()),
        ]
    );
}
