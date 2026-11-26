use super::*;
use anyhow::Result;
use flate2::{write::GzEncoder, Compression};
use serde_json::json;
use std::{
    cell::Cell,
    fs,
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tar::{Builder, Header};
use zip::{write::FileOptions, ZipWriter};

#[test]
fn release_tags_and_update_versions_are_strict_and_numeric() {
    for (input, expected) in [
        ("v26.11.9", "26.11.9"),
        ("v2.7.9", "2.7.9"),
        ("2.7.9", "2.7.9"),
        (" v1.2.3 ", "1.2.3"),
    ] {
        assert_eq!(release_tag(input), (expected.into(), true));
    }
    for input in [
        "",
        "v",
        "v2.7_rc6",
        "v2.7.9_rc1",
        "2.7.9-rc1",
        "latest",
        "v2..7",
    ] {
        assert_eq!(release_tag(input), (String::new(), false), "{input}");
    }

    assert_eq!(parse_semver("v1.2.3"), ([1, 2, 3], true));
    assert_eq!(parse_semver("1.4.0-rc1"), ([1, 4, 0], true));
    assert_eq!(parse_semver("nightly"), ([0, 0, 0], false));
    for (current, latest, expected) in [
        ("v1.0.5", "v1.0.6", true),
        ("v1.0.6", "v1.0.6", false),
        ("v1.0.6", "v1.0.5", false),
        ("1.0.0", "v1.2.0", true),
        ("dev", "v1.0.0", true),
        ("", "v1.0.0", true),
        ("v1.0.0", "", false),
        ("v1.0", "v1.0.1", true),
        // OpenVPN package revisions do not create an upstream update.
        ("2.6.11-2ubuntu1", "2.6.11-0ubuntu0.1", false),
        ("2.7.9", "2.7.10", true),
    ] {
        assert_eq!(
            version_less(current, latest),
            expected,
            "{current} -> {latest}"
        );
    }
}

#[tokio::test]
async fn update_check_uses_injected_release_metadata() {
    let status = check_update_with(|| async {
        Ok(ReleaseInfo {
            tag_name: "v9.8.7".into(),
            body: " notes\n".into(),
            html_url: "https://example.invalid/release".into(),
            ..ReleaseInfo::default()
        })
    })
    .await
    .unwrap();
    assert!(status.has_update);
    assert_eq!(status.latest, "v9.8.7");
    assert_eq!(status.notes, "notes");
    assert_eq!(status.url, "https://example.invalid/release");

    let release: ReleaseInfo = serde_json::from_value(json!({
        "tag_name": "v1.2.3",
        "name": null,
        "body": null,
        "html_url": null,
        "assets": [{
            "name": "fanout-linux-amd64.tar.gz",
            "browser_download_url": "https://example.invalid/fanout.tar.gz",
            "digest": null
        }]
    }))
    .unwrap();
    assert_eq!(release.tag_name, "v1.2.3");
    assert!(release.name.is_empty());
    assert!(release.body.is_empty());
    assert!(release.html_url.is_empty());
    assert_eq!(release.assets.len(), 1);
    assert!(release.assets[0].digest.is_empty());
}

#[test]
fn client_versions_and_openvpn_gap_notes_are_parsed() {
    for (output, expected) in [
        ("Xray 26.2.27 (Ruyi MCP)\n", "26.2.27"),
        ("Xray 1.5.1 (Ruyi EMC)\nsome noise\n", "1.5.1"),
        ("Xray-core v25.10.5\n", "25.10.5"),
        ("  Xray 26.2.27 (Ruyi MCP)  \n", "26.2.27"),
        ("", ""),
        ("xray\n", ""),
        ("openvpn: not found\n", ""),
    ] {
        assert_eq!(parse_xray_version(output), expected);
    }
    let openvpn = "OpenVPN 2.6.8 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4]\nlibrary versions:\n  OpenSSL 3.0.13\n";
    assert_eq!(parse_openvpn_version(openvpn), "2.6.8");
    assert_eq!(parse_openvpn_version("OpenVPN\n"), "");
    assert_eq!(
        parse_openvpn_version("bash: openvpn: command not found\n"),
        ""
    );
    assert!(ovpn_gap_note("deb", "2.7.9", "", "2.7.9").is_empty());
    assert!(ovpn_gap_note("deb", "2.6.19", "2.7.9", "2.7.9").is_empty());
    let deb_gap = ovpn_gap_note("deb", "2.6.19", "2.6.20-1ubuntu1", "2.7.9");
    assert!(deb_gap.contains("2.6.20"));
    assert!(deb_gap.contains("官方 2.7.9"));
    let rpm_gap = ovpn_gap_note("rpm", "2.6.19", "", "2.7.9");
    assert!(rpm_gap.contains("本机源里没有"));
    assert!(rpm_gap.contains("Copr"));
}

#[test]
fn xray_assets_and_update_targets_match_official_releases() {
    for (arch, expected) in [
        ("amd64", "Xray-linux-64.zip"),
        ("386", "Xray-linux-32.zip"),
        ("arm64", "Xray-linux-arm64-v8a.zip"),
        ("arm", "Xray-linux-arm32-v7a.zip"),
        ("riscv64", "Xray-linux-riscv64.zip"),
        ("mips64le", "Xray-linux-mips64le.zip"),
        ("ppc64le", "Xray-linux-ppc64le.zip"),
    ] {
        assert_eq!(xray_asset_for_arch(arch), expected);
    }

    let work = Path::new("/var/lib/fanout");
    let owned = work.join("bin/xray");
    assert_eq!(xray_update_target(work, "", "native").0, "");
    assert!(!xray_update_target(work, "", "").1.is_empty());
    assert!(!xray_update_target(work, "", "3x-ui").1.is_empty());
    assert!(xray_update_target(work, "/usr/local/bin/xray", "native")
        .1
        .contains("包管理器"));
    assert_eq!(
        xray_update_target(work, "/var/lib/fanout/bin/../bin/xray", "native"),
        (path_string(&owned), String::new())
    );
}

fn write_zip(path: &Path, files: &[(&str, &str)]) -> Result<()> {
    let mut archive = ZipWriter::new(fs::File::create(path)?);
    for (name, body) in files {
        let options: FileOptions<'_, ()> = FileOptions::default();
        archive.start_file(*name, options)?;
        archive.write_all(body.as_bytes())?;
    }
    archive.finish()?;
    Ok(())
}

fn write_tar_gz(path: &Path, files: &[(&str, &str)]) -> Result<()> {
    let encoder = GzEncoder::new(fs::File::create(path)?, Compression::default());
    let mut archive = Builder::new(encoder);
    for (name, body) in files {
        let mut header = Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(body.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, name, body.as_bytes())?;
    }
    archive.into_inner()?.finish()?;
    Ok(())
}

#[test]
fn archive_extraction_selects_the_binary_member() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let zip_path = temporary.path().join("xray.zip");
    write_zip(
        &zip_path,
        &[
            ("config.json", "{}"),
            ("bin/xray", "new xray"),
            ("geoip.dat", "data"),
        ],
    )?;
    let xray = temporary.path().join("xray");
    extract_from_zip(&zip_path, "xray", &xray)?;
    assert_eq!(fs::read_to_string(&xray)?, "new xray");
    assert!(extract_from_zip(&zip_path, "missing", &xray).is_err());

    let tar_path = temporary.path().join("fanout.tar.gz");
    write_tar_gz(
        &tar_path,
        &[("install.sh", "echo hi"), ("./fanout", "BINARY-CONTENT")],
    )?;
    let fanout = temporary.path().join("fanout");
    extract_binary(&tar_path, "fanout", &fanout)?;
    assert_eq!(fs::read(&fanout)?, b"BINARY-CONTENT");
    assert!(extract_binary(&tar_path, "missing", &fanout).is_err());
    Ok(())
}

#[test]
fn checksum_list_and_file_hashing_are_compatible() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let list = temporary.path().join("checksums.txt");
    fs::write(
        &list,
        "abc123  fanout-linux-amd64.tar.gz\ndef456 *fanout-linux-arm64.tar.gz\n",
    )?;
    assert_eq!(
        sha256_from_list(&list, "fanout-linux-amd64.tar.gz")?,
        "abc123"
    );
    assert_eq!(
        sha256_from_list(&list, "fanout-linux-arm64.tar.gz")?,
        "def456"
    );
    assert!(sha256_from_list(&list, "missing.tar.gz").is_err());

    let binary = temporary.path().join("fanout");
    fs::write(&binary, b"abc")?;
    assert_eq!(
        sha256_file(&binary)?,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(file_sha256(&binary)?, sha256_file(&binary)?);
    Ok(())
}

#[test]
fn binary_replacement_succeeds_and_rolls_back_a_failed_reload() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let target = temporary.path().join("xray");
    let pulled = temporary.path().join("pulled");
    fs::write(&target, b"old")?;
    fs::write(&pulled, b"new")?;

    replace_binary_with(&target, &pulled, None)?;
    assert_eq!(fs::read(&target)?, b"new");
    assert_eq!(fs::read(sibling_path(&target, ".prev"))?, b"old");

    fs::remove_file(sibling_path(&target, ".prev"))?;
    fs::write(&target, b"old-again")?;
    let reloads = Arc::new(AtomicUsize::new(0));
    let callback_reloads = Arc::clone(&reloads);
    let result = replace_binary_with(
        &target,
        &pulled,
        Some(&|| {
            if callback_reloads.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(anyhow!("reload rejected config"))
            } else {
                Ok(())
            }
        }),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&target)?, b"old-again");
    assert_eq!(reloads.load(Ordering::SeqCst), 2);
    assert!(!sibling_path(&target, ".new").exists());
    assert!(!sibling_path(&target, ".prev").exists());
    Ok(())
}

#[test]
fn os_release_and_distro_families_are_parsed() {
    let values = parse_os_release(
        "# Ubuntu 22.04.4 LTS\nNAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nexport HOME_URL=\"https://ubuntu.example/\"\nPRETTY_NAME='Ubuntu 22.04 LTS'\nJUNK\n",
    );
    assert_eq!(values.get("ID").map(String::as_str), Some("ubuntu"));
    assert_eq!(values.get("ID_LIKE").map(String::as_str), Some("debian"));
    assert_eq!(
        values.get("HOME_URL").map(String::as_str),
        Some("https://ubuntu.example/")
    );
    assert_eq!(
        values.get("PRETTY_NAME").map(String::as_str),
        Some("Ubuntu 22.04 LTS")
    );
    assert!(!values.contains_key("JUNK"));

    for (id, like, expected) in [
        ("ubuntu", "debian", "deb"),
        ("debian", "", "deb"),
        ("linuxmint", "ubuntu debian", "deb"),
        ("centos", "rhel fedora", "rpm"),
        ("rocky", "rhel", "rpm"),
        ("fedora", "", "rpm"),
        ("amzn", "", "rpm"),
        ("alpine", "", "alpine"),
        ("arch", "arch", "arch"),
        ("manjaro", "arch", "arch"),
        ("opensuse-leap", "suse", "suse"),
        ("sles", "", "suse"),
        ("openwrt", "", ""),
    ] {
        let map = HashMap::from([("ID".into(), id.into()), ("ID_LIKE".into(), like.into())]);
        assert_eq!(distro_family(&map), expected, "{id}");
    }
}

#[test]
fn package_upgrade_and_repository_query_plans_are_specific() {
    let all = |_name: &str| true;
    for (os_release, family) in [
        ("ID=ubuntu\nID_LIKE=debian\n", "deb"),
        ("ID=rocky\nID_LIKE=\"rhel fedora\"\n", "rpm"),
        ("ID=alpine\n", "alpine"),
        ("ID=arch\n", "arch"),
        ("ID=opensuse-leap\nID_LIKE=suse\n", "suse"),
    ] {
        let (steps, detected) = openvpn_upgrade_plan(os_release, all).unwrap();
        assert_eq!(detected, family);
        assert!(!steps.is_empty());
        for step in steps {
            let line = step.join(" ");
            assert!(
                line.contains("openvpn")
                    || matches!(
                        line.as_str(),
                        "apt-get update -qq"
                            | "apk update --no-cache"
                            | "zypper --non-interactive refresh"
                    )
            );
            assert!(!step.iter().any(|arg| arg == "-u" || arg == "--asdeps"));
        }
        let (_, query) = openvpn_repo_query_plan(family, all).unwrap();
        assert!(!query.is_empty());
    }

    let rocky = "ID=rocky\nID_LIKE=rhel\n";
    assert_eq!(
        openvpn_upgrade_plan(rocky, |name| name == "dnf").unwrap().0[0][0],
        "dnf"
    );
    assert_eq!(
        openvpn_upgrade_plan(rocky, |name| name == "yum").unwrap().0[0][0],
        "yum"
    );
    assert!(openvpn_upgrade_plan(rocky, |_| false).is_err());
    assert!(openvpn_upgrade_plan("ID=openwrt\n", all).is_err());
    assert!(openvpn_repo_query_plan("deb", |name| name != "apt-cache").is_err());

    let (steps, family) = wireguard_install_plan("ID=ubuntu\nID_LIKE=debian\n", all).unwrap();
    assert_eq!(family, "deb");
    assert_eq!(
        steps,
        vec![
            vec!["apt-get", "update", "-qq"],
            vec!["apt-get", "install", "-y", WIREGUARD_PKG],
        ]
    );
    assert!(wireguard_install_plan("ID=ubuntu\n", |name| name != "apt-get").is_err());
}

#[test]
fn package_manager_version_parsers_ignore_plugins_and_revisions() {
    assert_eq!(
        parse_apt_candidate(
            "openvpn:\n  Installed: 2.5.8-2ubuntu2\n  Candidate: 2.6.11-0ubuntu0.1\n"
        ),
        "2.6.11-0ubuntu0.1"
    );
    assert_eq!(parse_apt_candidate("openvpn:\n  Candidate: (none)\n"), "");
    assert_eq!(
        parse_dnf_list_row(
            "Installed Packages\nopenvpn.x86_64 1:2.5.8-1.el8 @System\nAvailable Packages\nopenvpn.x86_64 1:2.6.11-1.el8 appstream\n"
        ),
        "2.6.11-1.el8"
    );
    assert_eq!(
        parse_dnf_list_row("openvpn-2.4.11-1.el7.x86_64 2.4.11-1.el7 base\n"),
        "2.4.11-1.el7"
    );
    assert_eq!(
        parse_dnf_list_row(
            "Installed Packages\nopenvpn-auth-ldap.x86_64 2.0.4-1.el8 @System\nopenvpn.x86_64 1:2.5.8-1.el8 @System\n"
        ),
        "2.5.8-1.el8"
    );
    assert_eq!(
        parse_apk_policy(
            "openvpn-2.5.8-r0:\n  2.6.11-r0:\n    V: https://example.invalid/v3.21/main\n  2.5.8-r0:\n    V: https://example.invalid/v3.20/main\n"
        ),
        "2.6.11-r0"
    );
    assert_eq!(parse_apk_policy("ERROR: unable to select packages:\n"), "");
    assert_eq!(
        parse_colon_version("Name : openvpn\nVersion : 2.6.11-1\n"),
        "2.6.11-1"
    );
    assert_eq!(parse_colon_version("Versioning : rpm\n"), "");
}

#[test]
fn lock_detection_and_stale_index_messages_are_distinct() {
    let lock = anyhow!("exit status 100: E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4150393");
    assert!(looks_locked(&lock));
    let message = refresh_why("apt-get", &lock);
    assert!(message.contains("正被别的进程占用"));
    assert!(message.contains("可能偏旧"));
    assert!(!message.contains("4150393"));

    let network =
        anyhow!("exit status 100: E: Failed to fetch http://example.invalid connection timed out");
    assert!(!looks_locked(&network));
    assert!(refresh_why("apt-get", &network).contains("connection timed out"));
    assert_eq!(tail_lines("a\nb\nc\nd\ne\n", 2), "d\ne");
    assert_eq!(tail_lines("只有一行\n", 5), "只有一行");
    assert_eq!(tail_lines("", 3), "");
}

#[test]
fn debian_repository_inputs_and_versions_are_validated() {
    for value in [
        "noble",
        "bookworm",
        "resolute",
        "sid",
        "trixie",
        "ubuntu_24.04",
        "jammy-backports",
    ] {
        assert!(valid_deb_codename(value), "{value}");
    }
    for value in [
        "",
        "-noble",
        ".noble",
        "NOBLE",
        "no ble",
        "../../etc/passwd",
        "noble;rm",
        "a b",
    ] {
        assert!(!valid_deb_codename(value), "{value}");
    }
    assert_eq!(
        deb_codename(&parse_os_release("ID=linuxmint\nUBUNTU_CODENAME=noble\n")),
        "noble"
    );
    assert_eq!(
        deb_codename(&parse_os_release("VERSION_CODENAME=resolute\n")),
        "resolute"
    );
    assert_eq!(
        deb_codename(&parse_os_release("VERSION_CODENAME=\"2; wget x|sh\"\n")),
        ""
    );

    for (input, expected) in [
        ("2.7.1-resolute1", "2.7.1"),
        ("2.6.10-noble0", "2.6.10"),
        ("2.7.9", "2.7.9"),
    ] {
        assert_eq!(deb_stable_version(input), (expected.into(), true));
    }
    for input in [
        "2.7~alpha1-bookworm0",
        "2.7~rc1-questing1",
        "2.6-beta1-focal0",
        "1:2.7.1-1",
        "",
        "-resolute1",
        "2.x.1-foo0",
        "2..1-x",
    ] {
        assert_eq!(deb_stable_version(input), (String::new(), false), "{input}");
    }
    assert_eq!(deb_arch("x86_64"), "amd64");
    assert_eq!(deb_arch("aarch64"), "arm64");
    assert_eq!(deb_arch("386"), "i386");
    assert_eq!(deb_arch("mips64le"), "");
    assert!(valid_deb_apt_channel("stable"));
    assert!(valid_deb_apt_channel("release/2.7"));
    assert!(!valid_deb_apt_channel("release/2.6"));
}

#[test]
fn debian_package_index_and_official_target_selection_match_go() {
    let blob = "Package: openvpn-auth-ldap\nVersion: 0.0.5-1\n\nPackage: openvpn\r\nVersion: 2.7.1-resolute1\r\nDepends: libc6\r\n\r\nPackage: openvpn-systemd-resolved\nVersion: 1.3.1-1\n";
    assert_eq!(parse_deb_pkg_version(blob, "openvpn"), "2.7.1-resolute1");
    assert_eq!(
        parse_deb_pkg_version(blob, "openvpn-systemd-resolved"),
        "1.3.1-1"
    );
    assert_eq!(parse_deb_pkg_version(blob, "missing"), "");

    let pages = HashMap::from([
        (
            format!("{OVPN_APT_BASE}/release/2.7/dists/resolute/main/binary-amd64/Packages"),
            "Package: openvpn\nVersion: 2.7.1-resolute1\n",
        ),
        (
            format!("{OVPN_APT_BASE}/stable/dists/resolute/main/binary-amd64/Packages"),
            "Package: openvpn\nVersion: 2.6.20-resolute0\n",
        ),
        (
            format!("{OVPN_APT_BASE}/release/2.7/dists/noble/main/binary-amd64/Packages"),
            "Package: openvpn\nVersion: 2.7~alpha1-noble0\n",
        ),
        (
            format!("{OVPN_APT_BASE}/stable/dists/noble/main/binary-amd64/Packages"),
            "Package: openvpn\nVersion: 2.6.10-noble0\n",
        ),
    ]);
    let fetch = |url: &str| {
        pages
            .get(url)
            .map(|body| (*body).to_string())
            .ok_or_else(|| anyhow!("404"))
    };
    assert_eq!(
        ovpn_apt_repo_ver("resolute", "amd64", "2.7.0", fetch),
        ("release/2.7".into(), "2.7.1".into(), String::new())
    );
    let (channel, official, why) = ovpn_apt_repo_ver("noble", "amd64", "2.6.19", fetch);
    assert_eq!(channel, "");
    assert_eq!(official, "2.6.10");
    assert!(why.contains("不比本机新"));
    assert!(ovpn_apt_repo_ver("", "amd64", "2.6.19", fetch)
        .2
        .contains("代号"));

    for (have, repo, official, channel, target, target_channel) in [
        (
            "2.7.0",
            "2.6.20-resolute0",
            "2.7.1",
            "release/2.7",
            "2.7.1",
            "release/2.7",
        ),
        (
            "2.6.19",
            "2.6.20-ubuntu1",
            "2.6.10",
            "stable",
            "2.6.20-ubuntu1",
            "",
        ),
        ("2.6.19", "2.7.1-1", "2.7.1", "release/2.7", "2.7.1-1", ""),
        ("2.7.9", "2.7.9-1", "2.7.9", "release/2.7", "", ""),
    ] {
        assert_eq!(
            openvpn_pick_target(have, repo, official, channel),
            (target.into(), target_channel.into())
        );
    }
    assert_eq!(
        ovpn_apt_repo_line("release/2.7", "amd64", "resolute"),
        format!("deb [arch=amd64 signed-by={OVPN_APT_KEYRING}] {OVPN_APT_BASE}/release/2.7 resolute main\n")
    );
}

#[tokio::test]
async fn openvpn_decision_is_pure_and_only_writes_a_newer_official_source() {
    let probes = Cell::new(0);
    let decision = decide_openvpn_upgrade_with(
        "ID=ubuntu\nVERSION_CODENAME=noble\nID_LIKE=debian\n",
        "2.6.19",
        "amd64",
        |_| true,
        |family| {
            probes.set(probes.get() + 1);
            assert_eq!(family, "deb");
            RepoLatest {
                version: "2.6.20-1ubuntu1".into(),
                ..RepoLatest::default()
            }
        },
        |url| {
            if url.contains("/release/2.7/") {
                Ok("Package: openvpn\nVersion: 2.7.1-noble0\n".into())
            } else {
                Ok("Package: openvpn\nVersion: 2.6.10-noble0\n".into())
            }
        },
        || false,
        |_, _| false,
        true,
    );
    assert_eq!(probes.get(), 1);
    assert_eq!(decision.family, "deb");
    assert_eq!(decision.target, "2.7.1");
    assert_eq!(decision.channel, "release/2.7");
    assert!(decision.needs_write);
    assert!(decision.official_why.is_empty());

    let probes = Cell::new(0);
    let decision = decide_openvpn_upgrade_with(
        "ID=ubuntu\nVERSION_CODENAME=noble\nID_LIKE=debian\n",
        "2.6.19",
        "amd64",
        |_| true,
        |_| {
            probes.set(probes.get() + 1);
            RepoLatest::default()
        },
        |_| Err(anyhow!("must not fetch")),
        || panic!("must not inspect apt files"),
        |_, _| panic!("must not inspect apt files"),
        false,
    );
    assert_eq!(probes.get(), 0);
    assert!(decision.steps.len() >= 2);
    assert!(decision.target.is_empty());
    assert!(!decision.needs_write);
}

#[tokio::test]
async fn apt_repository_install_verifies_the_pinned_key_and_pins_the_source() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let key = temporary.path().join("keyrings/openvpn.asc");
    let fixture = temporary.path().join("fixture.asc");
    fs::write(&fixture, b"official key fixture")?;
    let files = AptRepoFiles {
        keyring: key.clone(),
        sources: temporary.path().join("sources.list.d/fanout-openvpn.list"),
        legacy_sources: temporary.path().join("sources.list"),
        key_url: "https://example.invalid/key".into(),
        key_sha256: sha256_file(&fixture)?,
    };
    install_openvpn_apt_repo_with(
        files.clone(),
        "release/2.7",
        "amd64",
        "noble",
        |_, destination| {
            let fixture = fixture.clone();
            let destination = destination.to_path_buf();
            async move {
                fs::copy(fixture, destination)?;
                Ok(())
            }
        },
    )
    .await?;
    assert_eq!(fs::read(&key)?, b"official key fixture");
    assert!(openvpn_apt_repo_wired_with(&files));
    assert!(openvpn_apt_repo_has_channel_with(
        &files,
        "release/2.7",
        "noble"
    ));
    assert!(openvpn_apt_repo_ours_with(&files));
    let source = fs::read_to_string(&files.sources)?;
    assert!(source.contains("arch=amd64"));
    assert!(source.contains("signed-by="));

    let bad_files = AptRepoFiles {
        keyring: temporary.path().join("wrong-key.asc"),
        sources: temporary.path().join("wrong-source.list"),
        key_sha256: "0".repeat(64),
        ..files.clone()
    };
    assert!(install_openvpn_apt_repo_with(
        bad_files.clone(),
        "release/2.7",
        "amd64",
        "noble",
        |_, destination| {
            let fixture = fixture.clone();
            let destination = destination.to_path_buf();
            async move {
                fs::copy(fixture, destination)?;
                Ok(())
            }
        },
    )
    .await
    .is_err());
    assert!(!bad_files.keyring.exists());
    assert!(!bad_files.sources.exists());

    let mut invalid_files = files.clone();
    invalid_files.keyring = temporary.path().join("unused.asc");
    assert!(install_openvpn_apt_repo_with(
        invalid_files,
        "release/2.6",
        "amd64",
        "noble;rm",
        |_, _| async { panic!("invalid input must be rejected before download") },
    )
    .await
    .is_err());
    Ok(())
}

#[test]
fn source_versions_paths_and_assets_are_security_checked() -> Result<()> {
    for version in ["2.7.9", "2.6.19", "1.0.0", "2.7.10", "1234.5.6"] {
        assert!(ovpn_src_version_ok(version), "{version}");
    }
    for version in [
        "",
        "2.7",
        "2",
        "2.7.9.1",
        "2.7~alpha1",
        "2.7.9-1ubuntu1",
        "2.7.9a",
        "../../etc/passwd",
        "2.7/9",
        "v2.7.9",
        "2.7.",
        ".2.7",
        "12345.1.1",
        "$(reboot)",
    ] {
        assert!(!ovpn_src_version_ok(version), "{version}");
    }
    assert_eq!(ovpn_src_tar_name("2.7.9"), "openvpn-2.7.9.tar.gz");
    assert_eq!(ovpn_src_prefix("2.7.9"), "/usr/local/fanout-openvpn/2.7.9");
    assert_eq!(
        ovpn_src_bin("2.7.9"),
        "/usr/local/fanout-openvpn/2.7.9/sbin/openvpn"
    );
    assert!(ovpn_src_build_dir("2.7.9").starts_with("/var/lib/fanout/"));

    let digest = "c42a6ed892ddfe2d6e3317a5040f19bec5827564affb2fe3f2b3904a94daacb1";
    let release = ReleaseInfo {
        tag_name: "v2.7.9".into(),
        assets: vec![
            ReleaseAsset {
                name: "openvpn-2.7.9.tar.gz".into(),
                url: "https://github.com/OpenVPN/openvpn/releases/download/v2.7.9/openvpn-2.7.9.tar.gz".into(),
                digest: format!("sha256:{digest}"),
            },
            ReleaseAsset {
                name: "openvpn-2.7.9.tar.gz.asc".into(),
                url: "https://github.com/OpenVPN/openvpn/releases/download/v2.7.9/openvpn-2.7.9.tar.gz.asc".into(),
                digest: String::new(),
            },
        ],
        ..ReleaseInfo::default()
    };
    let (tar, asc, got_digest) = ovpn_src_assets(Some(&release), "2.7.9")?;
    assert!(tar.ends_with("openvpn-2.7.9.tar.gz"));
    assert!(asc.ends_with("openvpn-2.7.9.tar.gz.asc"));
    assert_eq!(got_digest, digest);
    assert!(ovpn_src_assets(Some(&release), "2.7~alpha1").is_err());
    assert!(ovpn_src_assets(None, "2.7.9").is_err());

    let mut hostile = release.clone();
    hostile.assets[0].url = "https://evil.example/openvpn-2.7.9.tar.gz".into();
    assert!(ovpn_src_assets(Some(&hostile), "2.7.9").is_err());
    let mut no_digest = release;
    no_digest.assets[0].digest.clear();
    assert!(ovpn_src_assets(Some(&no_digest), "2.7.9").is_err());
    Ok(())
}

#[test]
fn source_dependency_configure_and_eligibility_plans_match_go() {
    let configure = ovpn_src_configure_argv("/usr/local/fanout-openvpn/2.7.9");
    assert_eq!(
        configure,
        vec![
            "./configure",
            "--prefix=/usr/local/fanout-openvpn/2.7.9",
            "--disable-dco",
            "--disable-plugin-auth-pam",
            "--disable-unit-tests",
        ]
    );
    for (cpus, jobs) in [(0, 1), (1, 1), (2, 2), (4, 4), (64, 4)] {
        assert_eq!(ovpn_src_make_jobs(cpus), jobs);
    }
    for family in ["rpm", "alpine", "arch", "suse", "", "gentoo"] {
        assert!(ovpn_src_deps(family).is_empty());
    }
    let dependencies = ovpn_src_deps("deb");
    assert_eq!(dependencies.len(), 2);
    assert_eq!(
        &dependencies[1][4..],
        &[
            "build-essential",
            "pkg-config",
            "libssl-dev",
            "libcap-ng-dev",
            "liblzo2-dev",
            "liblz4-dev",
            "gnupg"
        ]
    );
    assert!(dependencies[1].contains(&"--no-install-recommends".into()));

    for (family, have, target, upstream, built, expected) in [
        ("deb", "2.6.19", "", "2.7.9", "", true),
        ("deb", "2.7.9", "", "2.7.9", "2.7.9", false),
        ("deb", "2.7.9", "", "2.7.10", "2.7.9", true),
        ("deb", "2.6.19", "2.7.9", "2.7.9", "", false),
        ("deb", "2.6.19", "2.7.1", "2.7.9", "", true),
        ("deb", "2.8.0", "", "2.7.9", "", false),
        ("deb", "2.6.19", "", "", "", false),
        ("rpm", "2.6.19", "", "2.7.9", "", false),
    ] {
        assert_eq!(
            openvpn_can_build_source(family, have, target, upstream, built),
            expected
        );
    }
    let plan = openvpn_src_plan("2.7.9", "deb");
    for needle in [
        "https://github.com/OpenVPN/openvpn/releases/download/v2.7.9/openvpn-2.7.9.tar.gz",
        "openvpn-2.7.9.tar.gz.asc",
        "apt-get update -qq",
        "./configure --prefix=/usr/local/fanout-openvpn/2.7.9 --disable-dco",
        "sha256",
        "/usr/local/fanout-openvpn/2.7.9/sbin/openvpn",
    ] {
        assert!(plan.contains(needle), "missing {needle}");
    }
    assert!(plan.find("apt-get update -qq") < plan.find("下载 https://github.com/"));
    assert!(plan.find("下载 https://github.com/") < plan.find("验签名"));
    assert_eq!(openvpn_src_plan("2.7~alpha1", "deb"), "");
}

#[test]
fn gpg_colon_and_status_fixtures_are_parsed_without_false_positives() {
    const COLONS: &str = "pub:-:4096:1:12F5F7B42F2B01E7:1486642505:1801998002::-:::scESC::::::23::0:\nfpr:::::::::F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7:\nuid:-::::1681940617::B8CF41916373C41518C22DFC73DD57DAE9F55A95::OpenVPN::::::::::0:\nsub:-:4096:1:822F6DF096D04874:1782904337:1814349583:::::s::::::23:\nfpr:::::::::33DA8C9EAE0EAE8C73172C10822F6DF096D04874:\n";
    assert_eq!(
        gpg_key_fingerprints(COLONS),
        vec![
            "F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7",
            "33DA8C9EAE0EAE8C73172C10822F6DF096D04874",
        ]
    );
    assert_eq!(
        gpg_key_fingerprints("fpr:::::::::TOOSHORT:\nfpr:::"),
        Vec::<String>::new()
    );

    const STATUS: &str = "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 822F6DF096D04874 OpenVPN\n[GNUPG:] VALIDSIG 33DA8C9EAE0EAE8C73172C10822F6DF096D04874 2026-11-05 1793885101 0 4 0 1 10 00 F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7\n";
    assert_eq!(
        gpg_signer_fingerprint(STATUS),
        "33DA8C9EAE0EAE8C73172C10822F6DF096D04874"
    );
    assert!(ovpn_src_pinned_signer(&gpg_sig_primary_fingerprint(STATUS)));
    assert_eq!(
        gpg_signer_fingerprint("[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 822F6DF096D04874 OpenVPN\n"),
        ""
    );
    assert_eq!(
        gpg_signer_fingerprint(
            "[GNUPG:] VALIDSIG 33DA8C9EAE0EAE8C73172C10822F6DF096D04874 2026-11-05 1\n"
        ),
        ""
    );
    assert_eq!(
        gpg_sig_primary_fingerprint("[GNUPG:] VALIDSIG 33DA8C9EAE0EAE8C73172C10822F6DF096D04874"),
        ""
    );
    assert!(ovpn_src_is_sha256(&"a".repeat(64)));
    assert!(!ovpn_src_is_sha256(&"a".repeat(40)));
    assert!(ovpn_src_is_fingerprint(&"a".repeat(40)));
    assert!(!ovpn_src_is_fingerprint(&"a".repeat(64)));
}

#[test]
fn source_records_and_deletion_paths_are_validated() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let record_path = temporary.path().join("nested/source.json");
    let record = OpenVPNSourceBuild {
        version: "2.7.9".into(),
        prefix: ovpn_src_prefix("2.7.9"),
        bin: ovpn_src_bin("2.7.9"),
        sha256: "a".repeat(64),
        signer: OVPN_SRC_SIGNERS[0].into(),
        built_at: "2026-11-26T00:00:00Z".into(),
    };
    write_openvpn_src_record_at(&record_path, &record)?;
    assert_eq!(read_openvpn_src_record_at(&record_path), Some(record));

    let invalid = OpenVPNSourceBuild {
        version: "../../etc".into(),
        ..OpenVPNSourceBuild::default()
    };
    assert!(write_openvpn_src_record_at(&record_path, &invalid).is_err());
    assert!(read_openvpn_src_record_at(&temporary.path().join("missing.json")).is_none());

    for (prefix, version) in [
        ("/usr/local/fanout-openvpn/2.7.9", "2.7.9"),
        ("/usr/local/fanout-openvpn/2.6.19", "2.6.19"),
    ] {
        assert!(ovpn_src_deletable(prefix, version));
    }
    for (prefix, version) in [
        ("/", ""),
        ("/usr", "2.7.9"),
        ("/etc", "2.7.9"),
        ("/usr/sbin/openvpn", "2.7.9"),
        ("/usr/local/fanout-openvpn", "2.7.9"),
        ("/usr/local/fanout-openvpn/2.6.19", "2.7.9"),
        ("/usr/local/fanout-openvpn/../etc", "2.7.9"),
        ("", "2.7.9"),
    ] {
        assert!(!ovpn_src_deletable(prefix, version), "{prefix} / {version}");
    }
    Ok(())
}

#[test]
fn source_build_lock_and_job_progress_are_consistent() {
    assert!(ovpn_build_start());
    assert!(!ovpn_build_start());
    ovpn_build_finish();
    assert!(ovpn_build_start());
    ovpn_build_finish();
    assert_eq!(OPENVPN_BUILD_STEPS.len(), B_STEP_INSTALL + 1);
    assert!(B_STEP_DEPS < B_STEP_SIGN);
}

#[tokio::test]
async fn source_build_job_reports_failure() {
    let job = SourceBuildJob::new("2.7.9");
    job.set(B_STEP_DEPS, "failed", "dependency install failed")
        .await;
    job.finish().await;
    let view = job.view().await;
    assert_eq!(view.status, "failed");
    assert_eq!(view.steps[B_STEP_DEPS].status, "failed");
    assert_eq!(view.steps[B_STEP_DEPS].detail, "dependency install failed");
}

#[test]
fn warp_versions_and_official_package_index_are_four_component_numeric() {
    assert!(warp_version_less("2026.8.2115.0", "2026.8.2116.0"));
    assert!(!warp_version_less("2026.8.2115.0", "2026.8.2115.0"));
    assert!(warp_version_less("2026.8.2115", "2026.8.2115.1"));
    assert!(!warp_version_less("2026.10.0.0", "2026.9.99.99"));
    assert_eq!(
        warp_version_parts("v2026.8.2115.0"),
        Some(vec![2026, 8, 2115, 0])
    );
    assert_eq!(warp_version_parts("2026.8.x"), None);
    assert_eq!(
        parse_warp_pkg_version(
            "Package: other\nVersion: 1\n\nPackage: cloudflare-warp\nVersion: 2026.8.2115.0\n"
        ),
        "2026.8.2115.0"
    );
    assert_eq!(
        parse_warp_codenames(" noble, bookworm, ,trixie "),
        vec!["noble", "bookworm", "trixie"]
    );
}

#[tokio::test]
async fn warp_latest_uses_only_official_indexes_and_falls_back() {
    let visited = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&visited);
    let latest = warp_latest_version_with(move |url| {
        let seen = Arc::clone(&seen);
        async move {
            seen.lock().unwrap().push(url.clone());
            if url.contains("/noble/") {
                Ok("Package: cloudflare-warp\nVersion: 2026.8.2115.0\n".into())
            } else {
                Err(anyhow!("404"))
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(latest, "2026.8.2115.0");
    let visited = visited.lock().unwrap();
    assert_eq!(visited.len(), 1);
    assert!(visited[0].starts_with("https://pkg.cloudflareclient.com/dists/noble/"));

    let error = warp_latest_version_with(|_| async { Err(anyhow!("offline")) })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("offline"));
}

#[test]
fn client_status_json_preserves_go_string_fields_and_omitempty_bools() -> Result<()> {
    let mut assessment = ClientBinAssessment::default();
    assessment.openvpn_official = "2.7.1".into();
    assessment.openvpn_apt = "2.6.19".into();
    assessment.openvpn_from_official = true;
    assessment.status.openvpn_stale = false;
    assessment.status.openvpn_repo_wired = true;
    assessment.status.openvpn_can_build = false;
    assessment.status.openvpn_source_active = false;
    assessment.status.warp_can_apply = false;
    // Prove the adapter replaces the pre-existing model's string field.
    assessment.status.openvpn_from_official = "wrong model type".into();

    let value = client_bin_status_json_from(&assessment)?;
    assert_eq!(value["openvpn_official"], json!("2.7.1"));
    assert_eq!(value["openvpn_apt"], json!("2.6.19"));
    assert_eq!(value["openvpn_from_official"], json!(true));
    assert_eq!(value["openvpn_repo_wired"], json!(true));
    for key in [
        "openvpn_stale",
        "openvpn_can_build",
        "openvpn_source_active",
        "warp_can_apply",
    ] {
        assert!(value.get(key).is_none(), "{key} should be omitted");
    }
    assert_eq!(value["openvpn_updatable"], json!(false));

    let empty = client_bin_status_json_from(&ClientBinAssessment::default())?;
    assert!(empty.get("openvpn_official").is_none());
    assert!(empty.get("openvpn_apt").is_none());
    assert_eq!(empty["openvpn_from_official"], json!(false));
    let runtime = ClientRuntime::default();
    let _ = format!("{runtime:?}");
    Ok(())
}

#[test]
fn empty_command_plans_fail_without_executing_anything() {
    let error = run_repo_query(&[], Duration::from_secs(1)).unwrap_err();
    assert!(error.to_string().contains("空命令"));
    let (_, error) = run_package_cmd(&[]);
    assert!(error.is_err());
    let (_, error) = run_build_cmd(Duration::from_secs(1), Path::new("."), &[]);
    assert!(error.is_err());
    assert!(run_upgrade_steps_within(&[], Duration::ZERO).is_ok());
}
