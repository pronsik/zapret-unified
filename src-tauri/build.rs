fn main() {
    // На Windows нужен кастомный манифест requireAdministrator (UAC — обязателен для
    // WinDivert). Раньше здесь стоял ВТОРОЙ отдельный проход через крейт `winres` поверх
    // tauri_build::build() — два независимых прохода сборки Windows-ресурса конфликтуют
    // между собой на некоторых версиях MSVC-тулчейна и валят линковку с CVT1100/LNK1123.
    // Правильный путь — отдать манифест самому tauri-build через его API, он встроит
    // манифест в тот же проход, что и иконку/версию.
    #[cfg(target_os = "windows")]
    {
        let attrs = tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new()
                .app_manifest(include_str!("windows/app.manifest")),
        );
        tauri_build::try_build(attrs).expect("failed to run tauri-build (windows attributes)");
    }

    #[cfg(not(target_os = "windows"))]
    {
        tauri_build::build();
    }
}
