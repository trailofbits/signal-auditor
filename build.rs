use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &["proto/transparency.proto", "proto/vectors.proto"],
        &["proto/"],
    )?;
    Ok(())
}
