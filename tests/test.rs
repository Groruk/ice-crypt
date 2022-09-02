use ice_crypt::IceKey;

#[test]
fn new() {
    let ice1 = IceKey::new(0);
    let ice2 = IceKey::new(2);

    assert_eq!(1, ice1.size());
    assert_eq!(8, ice1.rounds());

    assert_eq!(2, ice2.size());
    assert_eq!(32, ice2.rounds());
}

#[test]
fn decrypt() {
    let key: Vec<u8> = vec![67, 83, 71, 79, 16, 54, 0, 0, 132, 13, 0, 0, 97, 3, 0, 0];

    let mut icekey = IceKey::new(2);
    icekey.set(key);

    let ctext: Vec<u8> = vec![19, 216, 51, 57, 205, 99, 155, 24];

    let ptext = icekey.decrypt(ctext);

    assert_eq!(ptext, vec![249, 199, 187, 183, 247, 131, 106, 190]);
}

#[test]
fn decrypt_all() {
    let key: Vec<u8> = vec![67, 83, 71, 79, 16, 54, 0, 0, 132, 13, 0, 0, 97, 3, 0, 0];

    let mut icekey = IceKey::new(2);
    icekey.set(key);

    let ctext: Vec<u8> = vec![19, 216, 51, 57, 205, 99, 155, 24, 63, 29, 177, 151, 21, 105, 27, 92, 185, 35, 148, 213, 51, 247, 168, 42, 218];
    let ptext = icekey.decrypt_all(ctext);

    assert_eq!(32, ptext.len());
    assert_eq!(ptext, vec![249, 199, 187, 183, 247, 131, 106, 190, 97, 204, 24, 123, 245, 67, 242, 95, 160, 80, 87, 100, 165, 240, 74, 138, 41, 167, 215, 173, 115, 133, 65, 218]);
}

#[test]
fn encrypt() {
    let key: Vec<u8> = vec![67, 83, 71, 79, 16, 54, 0, 0, 132, 13, 0, 0, 97, 3, 0, 0];

    let mut icekey = IceKey::new(2);
    icekey.set(key);

    let ptext: Vec<u8> = vec![249, 199, 187, 183, 247, 131, 106, 190];

    let ctext = icekey.encrypt(ptext);

    assert_eq!(ctext, vec![19, 216, 51, 57, 205, 99, 155, 24]);
}

#[test]
fn encrypt_all() {
    let key: Vec<u8> = vec![67, 83, 71, 79, 16, 54, 0, 0, 132, 13, 0, 0, 97, 3, 0, 0];

    let mut icekey = IceKey::new(2);
    icekey.set(key);

    let ptext: Vec<u8> = vec![249, 199, 187, 183, 247, 131, 106, 190, 97, 204, 24, 123, 245, 67, 242, 95, 160, 80, 87, 100, 165, 240, 74, 138, 0];
    let ctext: Vec<u8> = icekey.encrypt_all(ptext);

    assert_eq!(32, ctext.len());
    assert_eq!(ctext, vec![19, 216, 51, 57, 205, 99, 155, 24, 63, 29, 177, 151, 21, 105, 27, 92, 185, 35, 148, 213, 51, 247, 168, 42, 22, 80, 253, 87, 163, 6, 164, 45])
}