use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/proto/transparency.proto", "src/proto/vectors.proto"], &["src/proto"])?;
    Ok(())
}
