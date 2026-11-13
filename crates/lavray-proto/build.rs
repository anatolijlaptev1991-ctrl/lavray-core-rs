// SPDX-License-Identifier: GPL-3.0-only

//! Генерация prost/tonic типов и сервисов из proto/lavray.proto (волна 6).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // build_client(false): RPC CoreService.Connect конфликтует с клиентским
    // конструктором connect (ограничение tonic). Ядро — сервер; оболочка ходит
    // через ConnectRPC/HTTP, gRPC-клиент не требуется. Генерируем сервер+типы.
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/lavray.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/lavray.proto");
    Ok(())
}
