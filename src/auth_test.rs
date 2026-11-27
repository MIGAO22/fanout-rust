use super::*;

#[test]
fn empty_basepath_file_means_root_instead_of_regenerating() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("basepath"), "").unwrap();
    assert_eq!(
        load_basepath(temporary.path()).unwrap(),
        (String::new(), false)
    );
}

#[test]
fn missing_basepath_file_generates_once() {
    let temporary = tempfile::tempdir().unwrap();
    let (first, created) = load_basepath(temporary.path()).unwrap();
    assert!(created);
    assert!(!first.is_empty());
    let (second, created) = load_basepath(temporary.path()).unwrap();
    assert!(!created);
    assert_eq!(first, second);
}
