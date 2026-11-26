///|
fn hex_nibble(c : Byte) -> Int32 {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    -1
  }
}

///|
fn hex_to_bytes(hex : Bytes) -> Bytes {
  let n = hex.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(hex[i * 2])
    let lo = hex_nibble(hex[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn bytes_to_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
fn fp_from_hex(hex : Bytes) -> @field.Fp {
  match @field.Fp::from_be_bytes_strict(hex_to_bytes(hex)) {
    Some(x) => x
    None => abort("invalid hex for Fp")
  }
}

///|
fn fp2_from_hex(c1_hex : Bytes, c0_hex : Bytes) -> @field.Fp2 {
  @field.Fp2::new(fp_from_hex(c0_hex), fp_from_hex(c1_hex))
}

///|
fn u256_from_hex(hex : Bytes) -> @field.U256 {
  match @field.U256::from_be_bytes(hex_to_bytes(hex)) {
    Some(x) => x
    None => abort("invalid hex for U256")
  }
}

///|
fn p1_coords() -> (@field.Fp, @field.Fp) {
  (
    fp_from_hex(
      b"93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd",
    ),
    fp_from_hex(
      b"21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616",
    ),
  )
}

///|
fn p2_coords() -> (@field.Fp2, @field.Fp2) {
  (
    fp2_from_hex(
      b"85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141", b"3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b",
    ),
    fp2_from_hex(
      b"17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96", b"a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7",
    ),
  )
}

///|
test "Official Vector 1: Base pairing e(P2, P1), group order N, and inverse symmetry" {
  let (p1x, p1y) = p1_coords()
  let (p2x, p2y) = p2_coords()
  let e = @pairing.pair_coords(p2x, p2y, p1x, p1y)
  let expected = "256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f523" +
    "0167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e9091308310" +
    "5e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e" +
    "79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe" +
    "082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b" +
    "3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f" +
    "7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf06" +
    "6fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de786968" +
    "8ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d" +
    "1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db927" +
    "7f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a0426" +
    "36a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669"
  assert_eq(bytes_to_hex(e.to_bytes()), expected)
  assert_true(!e.is_one())
  // Order N in GT: e(P2, P1)^N == 1
  assert_true(e.cyclotomic_pow_u256(@field.order_n).is_one())
  // Negation / bilinearity with -1: e(-P2, P1) == e(P2, -P1) == e(P2, P1)^{-1} = conjugate
  let e_neg_q = @pairing.pair_coords(p2x, p2y.neg(), p1x, p1y)
  let e_neg_p = @pairing.pair_coords(p2x, p2y, p1x, p1y.neg())
  assert_eq(e_neg_q, e.conjugate())
  assert_eq(e_neg_p, e.conjugate())
  assert_true(e.mul(e_neg_q).is_one())
  // Verify pair_coords == final_exponentiation(miller_loop)
  let m = @pairing.miller_loop(p2x, p2y, p1x, p1y)
  assert_eq(@pairing.final_exponentiation(m), e)
}

///|
test "Official Vector 2: Part 2 Signature g = e(P_pub-s, P1) and bilinearity e(P2, P1)^ks" {
  let (p1x, p1y) = p1_coords()
  let (p2x, p2y) = p2_coords()
  let p_pub_s_x = fp2_from_hex(
    b"9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408", b"29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32",
  )
  let p_pub_s_y = fp2_from_hex(
    b"69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c25", b"41e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d",
  )
  let g = @pairing.pair_coords(p_pub_s_x, p_pub_s_y, p1x, p1y)
  let expected_g = "4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d" +
    "28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000" +
    "38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f" +
    "a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db" +
    "67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f" +
    "5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6" +
    "1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b" +
    "93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439" +
    "b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d" +
    "4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b" +
    "84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a" +
    "aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"
  assert_eq(bytes_to_hex(g.to_bytes()), expected_g)
  // Bilinearity: e(P2, P1)^ks == e(P_pub-s, P1)
  let ks = u256_from_hex(
    b"000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4",
  )
  let e_base = @pairing.pair_coords(p2x, p2y, p1x, p1y)
  assert_eq(e_base.cyclotomic_pow_u256(ks), g)
}

///|
test "Official Vectors 3 & 4: Part 3 Key Exchange g1 = e(de_B, R_A), g2 = e(de_A, R_B), and bilinearity" {
  let (p1x, p1y) = p1_coords()
  let (p2x, p2y) = p2_coords()
  let p_pub_e_x = fp_from_hex(
    b"9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed06283",
  )
  let p_pub_e_y = fp_from_hex(
    b"54e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210",
  )
  let de_a_x = fp2_from_hex(
    b"0fe8eab395199b56bf1d75bd2cd610b6424f08d1092922c5882b52dcd6ca832a", b"7da57bc50241f9e5bfddc075dd9d32c7777100d736916cfc165d8d36e0634cd7",
  )
  let de_a_y = fp2_from_hex(
    b"83a457daf52cad464c903b26062caf937bb40e37daded9eda401050e49c8ad0c", b"6970876b9aad1b7a50bb4863a11e574af1fe3c5975161d73de4c3af621fb1efb",
  )
  let de_b_x = fp2_from_hex(
    b"74ccc3ac9c383c60af083972b96d05c75f12c8907d128a17adafbab8c5a4acf7", b"01092ff4de89362670c21711b6dbe52dcd5f8e40c6654b3dece573c2ab3d29b2",
  )
  let de_b_y = fp2_from_hex(
    b"44b0294aa04290e1524ff3e3da8cfd432bb64de3a8040b5b88d1b5fc86a4ebc1", b"8cfc48fb4ff37f1e27727464f3c34e2153861ad08e972d1625fc1a7bd18d5539",
  )
  let r_a_x = fp_from_hex(
    b"7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265",
  )
  let r_a_y = fp_from_hex(
    b"a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599",
  )
  let r_b_x = fp_from_hex(
    b"861e91485fb7623d2794f495031a35598b493bd45be37813abc710fcc1f34482",
  )
  let r_b_y = fp_from_hex(
    b"32d906a469ebc1216a802a7052d5617cd430fb56fba729d41d9bd668e9eb9600",
  )
  let g1 = @pairing.pair_coords(de_b_x, de_b_y, r_a_x, r_a_y)
  let g2 = @pairing.pair_coords(de_a_x, de_a_y, r_b_x, r_b_y)
  let expected_g1 = "28542fb6954c84be6a5f2988a31cb6817ba0781966fa83d9673a9577d3c0c134" +
    "5e27c19fc02ed9ae37f5bb7be9c03c2b87de027539ccf03e6b7d36de4ab45cd1" +
    "a1abfcd30c57db0f1a838e3a8f2bf823479c978bd137230506ea6249c891049e" +
    "3497477913ab89f5e2960f382b1b5c8ee09de0fa498ba95c4409d630d343da40" +
    "4fec93472da33a4db6599095c0cf895e3a7b993ee5e4ebe3b9ab7d7d5ff2a3d1" +
    "647ba154c3e8e185dfc33657c1f128d480f3f7e3f16801208029e19434c733bb" +
    "73f21693c66fc23724db26380c526223c705daf6ba18b763a68623c86a632b05" +
    "0f63a071a6d62ea45b59a1942dff5335d1a232c9c5664fad5d6af54c11418b0d" +
    "8c8e9d8d905780d50e779067f2c4b1c8f83a8b59d735bb52af35f56730bde5ac" +
    "861ccd9978617267ce4ad9789f77739e62f2e57b48c2ff26d2e90a79a1d86b93" +
    "9b1ca08f64712e33aeda3f44bd6cb633e0f722211e344d73ec9bbebc92142765" +
    "6ba584ce742a2a3ab41c15d3ef94edeb8ef74a2bdcdaaecc09aba567981f6437"
  let expected_g2 = "1052d6e9d13e381909dff7b2b41e13c987d0a9068423b769480dacce6a06f492" +
    "5ffeb92ad870f97dc0893114da22a44dbc9e7a8b6ca31a0cf0467265a1fb48c7" +
    "2c5c3b37e4f2ff83db33d98c0317bcbbbbf4ac6df6b89eca58268b280045e612" +
    "6ced9e2d7c9cd3d5ad630defab0b831506218037ee0f861cf9b43c78434aec38" +
    "0ae7bf3e1aec0cb67a03440906c7dfb3bcd4b6eeebb7e371f0094ad4a816088d" +
    "98dbc791d0671caca12236cdf8f39e15aeb96faeb39606d5b04ac581746a663d" +
    "00dd2b7416baa91172e89d5309d834f78c1e31b4483bb97185931bad7be1b9b5" +
    "7ebac0349f8544469e60c32f6075fb0468a68147ff013537df792ffce024f857" +
    "10cc2b561a62b62da36aefd60850714f49170fd94a0010c6d4b651b64f3a3a5e" +
    "58c9687beddcd9e4fedab16b884d1fe6dfa117b2ab821f74e0bf7acda2269859" +
    "2a430968f16086061904ce201847934b11ca0f9e9528f5a9d0ce8f015c9aea79" +
    "934fdda6d3ab48c8571ce2354b79742aa498cb8cdde6bd1fa5946345a1a652f6"
  assert_eq(bytes_to_hex(g1.to_bytes()), expected_g1)
  assert_eq(bytes_to_hex(g2.to_bytes()), expected_g2)
  // Bilinearity checks: e(P2, P1)^ke == e(P2, P_pub-e), g^r_A == g1, g^r_B == g2, g1^r_B == g2^r_A == g3
  let ke = u256_from_hex(
    b"0002e65b0762d042f51f0d23542b13ed8cfa2e9a0e7206361e013a283905e31f",
  )
  let r_a = u256_from_hex(
    b"00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8",
  )
  let r_b = u256_from_hex(
    b"00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe",
  )
  let e_base = @pairing.pair_coords(p2x, p2y, p1x, p1y)
  let g_pub = @pairing.pair_coords(p2x, p2y, p_pub_e_x, p_pub_e_y)
  assert_eq(e_base.cyclotomic_pow_u256(ke), g_pub)
  assert_eq(g_pub.cyclotomic_pow_u256(r_a), g1)
  assert_eq(g_pub.cyclotomic_pow_u256(r_b), g2)
  let expected_g3 = "a76b6777ad87c9124c7d7065f74808db2e80371c70471580b0c7c457a79ea5e7" +
    "242fa31ff8e139fae169a16992f5f029162664ce78b333324b3bdb4c682bf9b2" +
    "0626d64dce603f332e9593f62b67a6b002deb6dd2e7d4fad3f33c38f202de204" +
    "5327490611b2ae6f849cf779b9b74ad9ba6cf397f61326120777ce4692f85dc2" +
    "adc269d1b62332582d823132a971275477a0cf1dccf4b2bf096d9110f74e2a01" +
    "b1ed06502333b2ab1ae697ea34f2ef8c6e47b0431831706cb5afcd75754fa795" +
    "28f65b3651e184bced030661ee4a8d670fbae26796e8cdb66f388ed6644af851" +
    "885c7f924cc7cb20968aa50e8230a3b39c2bb5dd4d753d94be5dd9a4272cf827" +
    "0da649cb8a63172f8fb028cd951e76215824a4ee28405d3c5e5dfda6c7ce293f" +
    "4a40ac8fc5b7168fa54ad3d0b81a0f8f50c164366ccdec1c9a40dce9f0a31133" +
    "35d89eaeb36f4d31bb6713064cda8835e2aa4529f42129327c6f7e8ab760654d" +
    "58d17e448f6d5cbca66bd7e33810d270dd3b9436b1bf46b9a17c9d11a5a6b148"
  assert_eq(bytes_to_hex(g1.cyclotomic_pow_u256(r_b).to_bytes()), expected_g3)
  assert_eq(bytes_to_hex(g2.cyclotomic_pow_u256(r_a).to_bytes()), expected_g3)
}

///|
test "Official Vectors 5, 6 & 7: Part 4 KEM/PKE g, w_A1, w_A2, and bilinearity" {
  let (p1x, p1y) = p1_coords()
  let (p2x, p2y) = p2_coords()
  let p_pub_e_x = fp_from_hex(
    b"787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff",
  )
  let p_pub_e_y = fp_from_hex(
    b"769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1",
  )
  let de_b_x = fp2_from_hex(
    b"94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683", b"115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b158",
  )
  let de_b_y = fp2_from_hex(
    b"7aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f", b"27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1",
  )
  let c1_a1_x = fp_from_hex(
    b"1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f",
  )
  let c1_a1_y = fp_from_hex(
    b"1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c",
  )
  let c1_a2_x = fp_from_hex(
    b"2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff",
  )
  let c1_a2_y = fp_from_hex(
    b"42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0",
  )
  let g = @pairing.pair_coords(p2x, p2y, p_pub_e_x, p_pub_e_y)
  let w_a1 = @pairing.pair_coords(de_b_x, de_b_y, c1_a1_x, c1_a1_y)
  let w_a2 = @pairing.pair_coords(de_b_x, de_b_y, c1_a2_x, c1_a2_y)
  let expected_g = "9746fc5b231cedf36f835c47893d63c6ff652bcb92375ce3c2ab256d1fd56413" +
    "232a2f80cfbae061f196bb99213d50306648ac33cdc78e8f8a1563ffbf3bd3eb" +
    "68e8a16c0ac905f692904abcc004b1acf12106bd0a15b6e708d76e72b9288ef2" +
    "9436a60c403f4f8bac4dd3e393e25419e634fc2b3daf247f6092a802f60d5c58" +
    "a140eaef3893d574cb83c01d951a53f51975760be57f3bbd89817498d2158352" +
    "95a2bcce25359d033fc654bd6a9e462e5bd0686ff6ddd7455f71fff15affd3f0" +
    "b04320190b1e90cedf6ac570147a23ae6f0eae45034e6c62124dd6e8978f78ad" +
    "a504e3b43c1dd36794217fa1b05ac046c4131854c3d3e3a5b5967a64a861f0a2" +
    "897f7b35d1c0e21d84d75cffac08c73e744a16a47ee76e28a0b03849888d10ff" +
    "24443bb424b12c41eaf6d34d925205901f5cba59cfeba35224660db3848b0bf5" +
    "0825403fb3f681ab2b036dbba25483d5cb98bd56f3df95f0a7a705a2f6fd804b" +
    "9ce7bc68062182cf5d9f4a98c5a4ed1f3b4ce4ea817d19ed7ef2ce98e6f5864d"
  let expected_w_a1 = "8eab0cd6d0c95a6bbb7051ac848fdfb9689e5e5c486b1294557189b338b53b1d" +
    "78082bb40152dc35ac774442cc6408ffd68494d9953d77bf55e30e84697f6674" +
    "5aaf52239e46b0373b3168bab75c32e048b5faebabfa1f7f9ba6b4c0c90e65b0" +
    "75f6a2d9ed54c87cddd2eaa787032320205e7ac7d7feaa8695ab2bf7f5710861" +
    "247c2034ccf4a1432da1876d023ad6d74ff1678fda3af37a3d9f613cde805798" +
    "8b07151bac93af48d78d86c26ea97f24e2dacc84104cce8791fe90ba61b2049c" +
    "aac6ab38ea07f9966173fd9bbf34aab58ee84cd3777a9fd00bbca1dc09cf8696" +
    "a1040465bd723ae513c4be3ef2cfdc088a935f0b207deed7aad5ce2fc37d4203" +
    "4d874a4ce9b3b58765b1252a0880952b4ff3c97ea1a4cfdc67a0a0072541a03d" +
    "3924eabc443b0503510b93bbcd98eb70e0192b821d14d69ccb2513a1a7421eb7" +
    "a018a035e8fb61f271de1c5b3e781c63508c113b3eac537805eae164d732fad0" +
    "56bea27c8624d5064c9c278a193d63f6908ee558df5f5e0721317fc6e829c242"
  let expected_w_a2 = "63253798b7535975a90f202561fc54570fee88bf69e3b7a512697069e59e1f5d" +
    "42d54b984af01d710ba0030c18738f6b14e4df472acaf89399228d85af117904" +
    "b426dff040c49f9a43bcd7fd7d757b7d1d8d7311c08fc3b57616c5ee137785a3" +
    "28d19396dbdfac50eee62b1c7f994bb6f9bd9efb2221a1be1b6eb3e8f71485b4" +
    "a3eef46e1b99f614d7bd7f57574ba7ebb502af0bdaba0787c5c4dbc56a344a25" +
    "a06790b605cea0bbaf34776d6b1fc0198a02d05bbaac6f64a555ab2ca576f0da" +
    "b405cbbf22197b94fd18d27da0b0e52c8754ee94279634691fea6e13ffd0584e" +
    "aa2a94a7e2259b671896302b4275ae3e8cf2010098d5beaf19d0a6e60354e1c5" +
    "5c97e64f848b06d39ba8828ff59502c081d3dae68f35f7e6448db96d220a0fba" +
    "02be03c51bf062b6f564ae0bfb42dca36e71d387512e3bccca3379b73ec47176" +
    "52be92fb9e78ba9e1d80a156065804935742dbd2b967543011aac53333909fbf" +
    "5fadec14a2fbd15248e77467442a69698246fb0314c7a8246d952219dd2144ed"
  assert_eq(bytes_to_hex(g.to_bytes()), expected_g)
  assert_eq(bytes_to_hex(w_a1.to_bytes()), expected_w_a1)
  assert_eq(bytes_to_hex(w_a2.to_bytes()), expected_w_a2)
  // Bilinearity checks: e(P2, P1)^ke == g, g^r_A1 == w_A1, g^r_A2 == w_A2
  let ke = u256_from_hex(
    b"0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22",
  )
  let r_a1 = u256_from_hex(
    b"000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
  )
  let r_a2 = u256_from_hex(
    b"0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  let e_base = @pairing.pair_coords(p2x, p2y, p1x, p1y)
  assert_eq(e_base.cyclotomic_pow_u256(ke), g)
  assert_eq(g.cyclotomic_pow_u256(r_a1), w_a1)
  assert_eq(g.cyclotomic_pow_u256(r_a2), w_a2)
}

///|
test "pair_product_coords matches pair_coords product and handles edge cases" {
  let (p1x, p1y) = p1_coords()
  let (p2x, p2y) = p2_coords()
  let p_pub_s_x = fp2_from_hex(
    b"9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408", b"29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32",
  )
  let p_pub_s_y = fp2_from_hex(
    b"69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c25", b"41e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d",
  )
  let c1_x = fp_from_hex(
    b"1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f",
  )
  let c1_y = fp_from_hex(
    b"1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c",
  )
  // General pair product: e(P2, P1) * e(P_pub-s, C1)
  let lhs = @pairing.pair_product_coords(
    p2x, p2y, p1x, p1y, p_pub_s_x, p_pub_s_y, c1_x, c1_y,
  )
  let rhs = @pairing.pair_coords(p2x, p2y, p1x, p1y).mul(
    @pairing.pair_coords(p_pub_s_x, p_pub_s_y, c1_x, c1_y),
  )
  assert_eq(lhs, rhs)
  // Cancellation check: e(P2, P1) * e(-P2, P1) == 1
  let cancel = @pairing.pair_product_coords(
    p2x,
    p2y,
    p1x,
    p1y,
    p2x,
    p2y.neg(),
    p1x,
    p1y,
  )
  assert_true(cancel.is_one())
  // Infinity sentinel edge cases
  let z1 = @field.Fp::zero()
  let z2 = @field.Fp2::zero()
  assert_true(@pairing.pair_coords(z2, z2, p1x, p1y).is_one())
  assert_true(@pairing.pair_coords(p2x, p2y, z1, z1).is_one())
  assert_eq(
    @pairing.pair_product_coords(z2, z2, p1x, p1y, p2x, p2y, p1x, p1y),
    @pairing.pair_coords(p2x, p2y, p1x, p1y),
  )
  assert_eq(
    @pairing.pair_product_coords(p2x, p2y, p1x, p1y, p2x, p2y, z1, z1),
    @pairing.pair_coords(p2x, p2y, p1x, p1y),
  )
  assert_true(
    @pairing.pair_product_coords(z2, z2, z1, z1, z2, z2, z1, z1).is_one(),
  )
  assert_true(@pairing.final_exponentiation(@field.Fp12::one()).is_one())
}
