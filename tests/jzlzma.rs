mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "jzlzma";
    const INPUT_FILE_NAME: &str = "jzlzma.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}
