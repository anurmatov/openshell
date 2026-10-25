// SPDX-License-Identifier: Apache-2.0

//! Export the canonical compiled Create projection for cross-language clients.
//! Run from the repository root; stdout is binary, never a request or credential.

use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::io::stdout()
        .lock()
        .write_all(&openshell_core::create_fingerprint::schema_descriptor_set()?)?;
    Ok(())
}
