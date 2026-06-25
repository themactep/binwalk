mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "littlefs";
    const INPUT_FILE_NAME: &str = "littlefs.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}
