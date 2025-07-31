use std::io::Result;
fn main() -> Result<()> {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "proto/transparency.proto",
                "proto/vectors.proto",
                "proto/key_transparency.proto",
            ],
            &["proto/"],
        )?;

    Ok(())
}
