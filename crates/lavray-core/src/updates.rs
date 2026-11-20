// SPDX-License-Identifier: GPL-3.0-only

//! `updates check`: проверка свежего релиза на GitHub (releases/latest)
//! против текущей версии ядра. Вывод: human или `--json`.

/// Запуск `updates check [flags]`; код возврата процесса.
///
/// Флаги: `--repo OWNER/NAME` (дефолт — репозиторий проекта),
/// `--json` (машиночитаемый вывод).
#[must_use]
pub fn run_check(args: &[String]) -> i32 {
    let mut repo = lavray_engine::updates::DEFAULT_REPO.to_string();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                i += 1;
                let Some(r) = args.get(i) else {
                    eprintln!("lavray-core updates: --repo требует значение");
                    return 2;
                };
                repo.clone_from(r);
            }
            "--json" => json = true,
            other => {
                eprintln!("lavray-core updates: неизвестный флаг {other:?}");
                return 2;
            }
        }
        i += 1;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let current = lavray_engine::updates::CURRENT_VERSION;
    match rt.block_on(lavray_engine::updates::check(&repo, current)) {
        Ok(info) => {
            if json {
                println!(
                    "{{\"current\":\"{}\",\"latest\":\"{}\",\"newer\":{},\"url\":\"{}\"}}",
                    info.current,
                    info.latest.replace('"', "\\\""),
                    info.newer,
                    info.url.replace('"', "\\\"")
                );
            } else if info.newer {
                println!(
                    "доступно обновление: {} → {} ({})",
                    info.current, info.latest, info.url
                );
            } else {
                println!("ядро актуально: {} (latest {})", info.current, info.latest);
            }
            0
        }
        Err(e) => {
            eprintln!("lavray-core updates: {e}");
            1
        }
    }
}
