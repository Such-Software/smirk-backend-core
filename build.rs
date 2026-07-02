//! Compile the gRPC proto(s). `protoc` is vendored (protoc-bin-vendored) so a
//! source build needs no system protobuf-compiler.

fn main() {
    // Point tonic-build/prost at the vendored protoc.
    if let Ok(protoc) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", protoc);
    }
    println!("cargo:rerun-if-changed=proto/nauthz.proto");
    tonic_build::configure()
        .build_client(false) // we only serve the admission service, never call it
        .compile_protos(&["proto/nauthz.proto"], &["proto"])
        .expect("compile proto/nauthz.proto");
}
