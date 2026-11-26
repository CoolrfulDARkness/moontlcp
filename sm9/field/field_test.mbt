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
fn fn_from_hex(hex : Bytes) -> @field.Fn {
  match @field.Fn::from_be_bytes_strict(hex_to_bytes(hex)) {
    Some(x) => x
    None => abort("invalid hex for Fn")
  }
}

///|
test "U256 wide arithmetic adc/sbb/mac edge cases" {
  let max = 0xFFFF_FFFF_FFFF_FFFFUL
  // adc overflow cases
  assert_eq(@field.adc(max, 1UL, 0UL), (0UL, 1UL))
  assert_eq(@field.adc(max, max, 1UL), (max, 1UL))
  assert_eq(@field.adc(0UL, 0UL, 1UL), (1UL, 0UL))
  assert_eq(
    @field.adc(0x8000_0000_0000_0000UL, 0x8000_0000_0000_0000UL, 0UL),
    (0UL, 1UL),
  )
  // sbb borrow cases
  assert_eq(@field.sbb(0UL, 1UL, 0UL), (max, 1UL))
  assert_eq(@field.sbb(0UL, 0UL, 1UL), (max, 1UL))
  assert_eq(@field.sbb(0UL, max, 1UL), (0UL, 1UL))
  assert_eq(@field.sbb(5UL, 5UL, 0UL), (0UL, 0UL))
  assert_eq(@field.sbb(5UL, 5UL, 1UL), (max, 1UL))
  assert_eq(
    @field.sbb(0x8000_0000_0000_0000UL, 0x7FFF_FFFF_FFFF_FFFFUL, 0UL),
    (1UL, 0UL),
  )
  // mac max-value 128-bit case: (2^64-1) + (2^64-1)^2 + (2^64-1) = 2^128 - 1
  assert_eq(@field.mac(max, max, max, max), (max, max))
  assert_eq(@field.mac(0UL, max, max, 0UL), (1UL, max - 1UL))
  assert_eq(
    @field.mac(0x123456789abcdef0UL, 0x100000000UL, 0x100000000UL, 0UL),
    (0x123456789abcdef0UL, 1UL),
  )
}

///|
test "U256 constants, encoding, comparison, bits, and ct_select" {
  assert_eq(@field.BN_T, 0x600000000058f98aUL)
  assert_true(@field.U256::zero().is_zero())
  assert_true(!@field.U256::one().is_zero())
  assert_eq(@field.U256::zero().cmp(@field.U256::zero()), 0)
  assert_eq(@field.U256::zero().cmp(@field.U256::one()), -1)
  assert_eq(@field.U256::one().cmp(@field.U256::zero()), 1)
  assert_eq(@field.order_n.cmp(@field.modulus_p), -1)
  assert_eq(@field.modulus_p.cmp(@field.order_n), 1)
  // Check bit_at on modulus_p
  assert_eq(@field.modulus_p.bit_at(0), 1U) // p is odd (...7d)
  assert_eq(@field.modulus_p.bit_at(1), 0U)
  assert_eq(@field.modulus_p.bit_at(2), 1U)
  assert_eq(@field.modulus_p.bit_at(255), 1U) // 0xb640... has MSB 1
  assert_eq(@field.modulus_p.bit_at(254), 0U)
  assert_eq(@field.modulus_p.bit_at(-1), 0U)
  assert_eq(@field.modulus_p.bit_at(256), 0U)
  // Roundtrip bytes
  let p_bytes = @field.modulus_p.to_be_bytes()
  assert_eq(
    bytes_to_hex(p_bytes),
    "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d",
  )
  assert_eq(@field.U256::from_be_bytes(p_bytes), Some(@field.modulus_p))
  assert_eq(@field.U256::from_be_bytes(b"short"), None)
  // ct_select and ct_eq
  let a = @field.modulus_p
  let b = @field.order_n
  assert_true(@field.U256::ct_select(a, b, @field.ct_mask(false)).ct_eq(a))
  assert_true(@field.U256::ct_select(a, b, @field.ct_mask(true)).ct_eq(b))
}

///|
test "Fn scalar field axioms, boundaries, and Part 2 KGC arithmetic" {
  let zero = @field.Fn::zero()
  let one = @field.Fn::one()
  let n_minus_1 = zero.sub(one)
  assert_true(zero.is_zero())
  assert_true(!one.is_zero())
  assert_eq(zero.inv(), None)
  assert_eq(one.inv(), Some(one))
  assert_true(n_minus_1.add(one).is_zero())
  assert_true(n_minus_1.mul(n_minus_1).ct_eq(one))
  assert_eq(
    bytes_to_hex(n_minus_1.to_be_bytes()),
    "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf24",
  )
  // Strict rejection for >= N and zero in nonzero
  assert_eq(@field.Fn::from_be_bytes_strict(@field.order_n.to_be_bytes()), None)
  assert_eq(
    @field.Fn::from_be_bytes_strict(@field.modulus_p.to_be_bytes()),
    None,
  )
  assert_eq(
    @field.Fn::from_be_bytes_nonzero(@field.U256::zero().to_be_bytes()),
    None,
  )
  assert_true(@field.Fn::from_u256_mod(@field.order_n).is_zero())
  assert_true(
    @field.Fn::from_be_bytes_mod(@field.order_n.to_be_bytes()).is_zero(),
  )
  // Verify Part 2 official scalar vector: t1 = H1 + ks, t2 = ks * t1^-1 mod N
  let ks = fn_from_hex(
    b"000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4",
  )
  let h1 = fn_from_hex(
    b"2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab",
  )
  let t1_expected = fn_from_hex(
    b"2acd7773bd808842f841d35f87070d795f6af8f3f08c915e760a451186b3f59f",
  )
  let t2_expected = fn_from_hex(
    b"291fe3cac8f58ad2dc462c8d4d578a94dafd5624ddc28e328d2936688a86cf1a",
  )
  let t1 = h1.add(ks)
  assert_true(t1.ct_eq(t1_expected))
  let t1_inv = match t1.inv() {
    Some(x) => x
    None => abort("t1 must be invertible")
  }
  assert_true(t1.mul(t1_inv).ct_eq(one))
  let t2 = ks.mul(t1_inv)
  assert_true(t2.ct_eq(t2_expected))
  // Verify l = (r - h) mod N from Part 2
  let r = fn_from_hex(
    b"00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  let h = fn_from_hex(
    b"823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb",
  )
  let l_expected = fn_from_hex(
    b"3406f1643496dff8385c82cf5f4442b0123e89abaf898013fb13ae36d9799108",
  )
  assert_true(r.sub(h).ct_eq(l_expected))
  // Multi-byte reduction (33 bytes = N * 256 + 7 -> 7 mod N)
  let n_bytes = @field.order_n.to_be_bytes()
  let ext = Bytes::makei(33, fn(i) { if i < 32 { n_bytes[i] } else { b'\x07' } })
  assert_true(@field.Fn::from_be_bytes_mod(ext).ct_eq(@field.Fn::from_u64(7UL)))
}

///|
test "Fp axioms, boundaries, P1 curve equation, sqrt, and Frobenius constants" {
  let zero = @field.Fp::zero()
  let one = @field.Fp::one()
  let p_minus_1 = zero.sub(one)
  assert_true(zero.is_zero())
  assert_true(one.is_one())
  assert_true(@field.Fp::b_const().ct_eq(@field.Fp::from_u64(5UL)))
  assert_true(@field.Fp::from_u64(1UL).is_one())
  assert_true(@field.Fp::from_u256(@field.modulus_p).is_zero())
  assert_true(p_minus_1.add(one).is_zero())
  assert_true(p_minus_1.sqr().is_one())
  assert_true(zero.inv().is_zero())
  assert_eq(zero.inv_checked(), None)
  assert_eq(one.inv_checked(), Some(one))
  // Strict rejection >= p
  assert_eq(
    @field.Fp::from_be_bytes_strict(@field.modulus_p.to_be_bytes()),
    None,
  )
  let max_bytes = Bytes::make(32, b'\xFF')
  assert_eq(@field.Fp::from_be_bytes_strict(max_bytes), None)
  assert_eq(@field.Fp::from_be_bytes_strict(b"1234"), None)
  // P1 curve equation: y^2 == x^3 + 5 (mod p)
  let x_p1 = fp_from_hex(
    b"93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd",
  )
  let y_p1 = fp_from_hex(
    b"21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616",
  )
  // Check Montgomery limbs match spec §1.2
  assert_true(
    x_p1.ct_eq(
      @field.Fp::from_raw_mont(
        0x22e935e29860501bUL, 0xa946fd5e0073282cUL, 0xefd0cec817a649beUL, 0x5129787c869140b5UL,
      ),
    ),
  )
  assert_true(
    y_p1.ct_eq(
      @field.Fp::from_raw_mont(
        0xee779649eb87f7c7UL, 0x15563cbdec30a576UL, 0x326353912824efbfUL, 0x7215717763c39828UL,
      ),
    ),
  )
  let lhs = y_p1.sqr()
  let rhs = x_p1.sqr().mul(x_p1).add(@field.Fp::b_const())
  assert_true(lhs.ct_eq(rhs))
  // Inverse and sqrt checks
  assert_true(x_p1.mul(x_p1.inv()).is_one())
  assert_true(x_p1.mul_by_5().ct_eq(x_p1.mul(@field.Fp::b_const())))
  assert_true(x_p1.triple().ct_eq(x_p1.add(x_p1).add(x_p1)))
  assert_eq(zero.sqrt(), Some(zero))
  match lhs.sqrt() {
    Some(r) => assert_true(r.ct_eq(y_p1) || r.neg().ct_eq(y_p1))
    None => abort("y_p1^2 must have a square root")
  }
  // Since p == 5 mod 8, 2 is a quadratic non-residue
  assert_eq(@field.Fp::from_u64(2UL).sqrt(), None)
  // Verify all 13 precomputed Montgomery Frobenius constants against spec §3.3 standard hex
  assert_eq(
    bytes_to_hex(@field.gamma_11().to_be_bytes()),
    "3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_12().to_be_bytes()),
    "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_13().to_be_bytes()),
    "6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_14().to_be_bytes()),
    "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_15().to_be_bytes()),
    "2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_21().to_be_bytes()),
    "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_22().to_be_bytes()),
    "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_23().to_be_bytes()),
    "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c",
  )
  assert_eq(
    bytes_to_hex(@field.gamma_24().to_be_bytes()),
    "b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249",
  )
  assert_eq(
    bytes_to_hex(@field.twist_frob_x1().to_be_bytes()),
    "b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a",
  )
  assert_eq(
    bytes_to_hex(@field.twist_frob_y1().to_be_bytes()),
    "49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c",
  )
  assert_eq(
    bytes_to_hex(@field.twist_frob_x2().to_be_bytes()),
    "b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249",
  )
  assert_eq(
    bytes_to_hex(@field.twist_frob_y2().to_be_bytes()),
    "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c",
  )
}

///|
test "Fp2 axioms, P2 twist curve equation y^2 = x^3 + 5u, and FE2OS c1||c0" {
  let x_p2_1 = fp_from_hex(
    b"85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141",
  )
  let x_p2_0 = fp_from_hex(
    b"3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b",
  )
  let y_p2_1 = fp_from_hex(
    b"17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96",
  )
  let y_p2_0 = fp_from_hex(
    b"a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7",
  )
  let x_p2 = @field.Fp2::new(x_p2_0, x_p2_1)
  let y_p2 = @field.Fp2::new(y_p2_0, y_p2_1)
  // P2 on E'(Fp2): y^2 == x^3 + 5u
  let lhs = y_p2.sqr()
  let rhs = x_p2.sqr().mul(x_p2).add(@field.Fp2::b_twist())
  assert_true(lhs.ct_eq(rhs))
  // sqr == mul(self, self)
  assert_true(x_p2.sqr().ct_eq(x_p2.mul(x_p2)))
  // mul_by_u and mul_by_5u consistency
  let u = @field.Fp2::new(@field.Fp::zero(), @field.Fp::one())
  assert_true(x_p2.mul_by_u().ct_eq(x_p2.mul(u)))
  assert_true(x_p2.mul_by_5u().ct_eq(x_p2.mul(@field.Fp2::b_twist())))
  // u^2 == -2
  assert_true(
    u.sqr().ct_eq(@field.Fp2::from_fp(@field.Fp::from_u64(2UL).neg())),
  )
  // Inversion
  assert_true(x_p2.mul(x_p2.inv()).is_one())
  assert_eq(@field.Fp2::zero().inv_checked(), None)
  // FE2OS order: c1 || c0
  let x_bytes = x_p2.to_bytes()
  assert_eq(x_bytes.length(), 64)
  assert_eq(
    bytes_to_hex(x_bytes),
    "85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d88061413722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b",
  )
  assert_eq(@field.Fp2::from_bytes_strict(x_bytes), Some(x_p2))
  // Reject >= p in either half
  let p_bytes = @field.modulus_p.to_be_bytes()
  let zero32 = Bytes::make(32, b'\x00')
  let bad_hi = Bytes::makei(64, fn(i) {
    if i < 32 {
      p_bytes[i]
    } else {
      zero32[i - 32]
    }
  })
  let bad_lo = Bytes::makei(64, fn(i) {
    if i < 32 {
      zero32[i]
    } else {
      p_bytes[i - 32]
    }
  })
  assert_eq(@field.Fp2::from_bytes_strict(bad_hi), None)
  assert_eq(@field.Fp2::from_bytes_strict(bad_lo), None)
  assert_eq(@field.Fp2::from_bytes_strict(zero32), None)
}

///|
test "Fp6 axioms, sparse mul_by_01/mul_by_1, inversion, and Frobenius" {
  let a = @field.Fp6::new(
    @field.Fp2::new(@field.Fp::from_u64(3UL), @field.Fp::from_u64(7UL)),
    @field.Fp2::new(@field.Fp::from_u64(11UL), @field.Fp::from_u64(13UL)),
    @field.Fp2::new(@field.Fp::from_u64(17UL), @field.Fp::from_u64(19UL)),
  )
  let b = @field.Fp6::new(
    @field.Fp2::new(@field.Fp::from_u64(23UL), @field.Fp::from_u64(29UL)),
    @field.Fp2::new(@field.Fp::from_u64(31UL), @field.Fp::from_u64(37UL)),
    @field.Fp2::new(@field.Fp::from_u64(41UL), @field.Fp::from_u64(43UL)),
  )
  // Commutativity, squaring, inversion
  assert_true(a.mul(b).ct_eq(b.mul(a)))
  assert_true(a.sqr().ct_eq(a.mul(a)))
  assert_true(a.mul(a.inv()).is_one())
  assert_eq(@field.Fp6::zero().inv_checked(), None)
  // mul_by_s
  let s = @field.Fp6::new(
    @field.Fp2::zero(),
    @field.Fp2::one(),
    @field.Fp2::zero(),
  )
  assert_true(a.mul_by_s().ct_eq(a.mul(s)))
  // mul_by_01 & mul_by_1
  let b0 = @field.Fp2::new(
    @field.Fp::from_u64(101UL),
    @field.Fp::from_u64(103UL),
  )
  let b1 = @field.Fp2::new(
    @field.Fp::from_u64(107UL),
    @field.Fp::from_u64(109UL),
  )
  let full_01 = @field.Fp6::new(b0, b1, @field.Fp2::zero())
  let full_1 = @field.Fp6::new(@field.Fp2::zero(), b1, @field.Fp2::zero())
  assert_true(a.mul_by_01(b0, b1).ct_eq(a.mul(full_01)))
  assert_true(a.mul_by_1(b1).ct_eq(a.mul(full_1)))
  // Frobenius p^2 == frobenius_p(frobenius_p(a)), and p^6 == identity
  assert_true(a.frobenius_p2().ct_eq(a.frobenius_p().frobenius_p()))
  assert_true(a.frobenius_p2().frobenius_p2().frobenius_p2().ct_eq(a))
}

///|
test "Fp12 axioms, Frobenius vs pow(p), mul_by_014, cyclotomic ops, and 384B FE2OS" {
  let a = @field.Fp12::new(
    @field.Fp6::new(
      @field.Fp2::new(@field.Fp::from_u64(2UL), @field.Fp::from_u64(3UL)),
      @field.Fp2::new(@field.Fp::from_u64(5UL), @field.Fp::from_u64(7UL)),
      @field.Fp2::new(@field.Fp::from_u64(11UL), @field.Fp::from_u64(13UL)),
    ),
    @field.Fp6::new(
      @field.Fp2::new(@field.Fp::from_u64(17UL), @field.Fp::from_u64(19UL)),
      @field.Fp2::new(@field.Fp::from_u64(23UL), @field.Fp::from_u64(29UL)),
      @field.Fp2::new(@field.Fp::from_u64(31UL), @field.Fp::from_u64(37UL)),
    ),
  )
  let b = @field.Fp12::new(
    @field.Fp6::new(
      @field.Fp2::new(@field.Fp::from_u64(41UL), @field.Fp::from_u64(43UL)),
      @field.Fp2::new(@field.Fp::from_u64(47UL), @field.Fp::from_u64(53UL)),
      @field.Fp2::new(@field.Fp::from_u64(59UL), @field.Fp::from_u64(61UL)),
    ),
    @field.Fp6::new(
      @field.Fp2::new(@field.Fp::from_u64(67UL), @field.Fp::from_u64(71UL)),
      @field.Fp2::new(@field.Fp::from_u64(73UL), @field.Fp::from_u64(79UL)),
      @field.Fp2::new(@field.Fp::from_u64(83UL), @field.Fp::from_u64(89UL)),
    ),
  )
  // Basic axioms
  assert_true(a.mul(b).ct_eq(b.mul(a)))
  assert_true(a.sqr().ct_eq(a.mul(a)))
  assert_true(a.mul(a.inv()).is_one())
  assert_eq(@field.Fp12::zero().inv_checked(), None)
  // mul_by_014 == full Fp12::mul with (a0 + b0*s) + (c0*s)*t
  let la = @field.Fp2::new(
    @field.Fp::from_u64(211UL),
    @field.Fp::from_u64(223UL),
  )
  let lb = @field.Fp2::new(
    @field.Fp::from_u64(227UL),
    @field.Fp::from_u64(229UL),
  )
  let lc = @field.Fp2::new(
    @field.Fp::from_u64(233UL),
    @field.Fp::from_u64(239UL),
  )
  let line_full = @field.Fp12::new(
    @field.Fp6::new(la, lb, @field.Fp2::zero()),
    @field.Fp6::new(@field.Fp2::zero(), lc, @field.Fp2::zero()),
  )
  assert_true(a.mul_by_014(la, lb, lc).ct_eq(a.mul(line_full)))
  // Frobenius vs direct exponentiation by p!
  let fp_direct = a.pow_u256(@field.modulus_p)
  assert_true(a.frobenius_p().ct_eq(fp_direct))
  assert_true(a.frobenius_p2().ct_eq(a.frobenius_p().frobenius_p()))
  assert_true(a.frobenius_p3().ct_eq(a.frobenius_p2().frobenius_p()))
  // p^6 == conjugate
  assert_true(a.frobenius_p3().frobenius_p3().ct_eq(a.conjugate()))
  // Project into cyclotomic subgroup G_{Phi_6}: f = (a^{p^6} * a^{-1})^{p^2 + 1}
  let f0 = a.conjugate().mul(a.inv())
  let f = f0.frobenius_p2().mul(f0)
  // In cyclotomic subgroup: conjugate == inv
  assert_true(f.mul(f.conjugate()).is_one())
  // cyclotomic_sqr == sqr
  assert_true(f.cyclotomic_sqr().ct_eq(f.sqr()))
  assert_true(f.cyclotomic_sqr().cyclotomic_sqr().ct_eq(f.sqr().sqr()))
  // cyclotomic_pow_t == pow_u256(BN_T) == cyclotomic_pow_u256(BN_T)
  let t_u256 = @field.U256::from_u64(@field.BN_T)
  let ft_direct = f.pow_u256(t_u256)
  assert_true(f.cyclotomic_pow_t().ct_eq(ft_direct))
  assert_true(f.cyclotomic_pow_u256(t_u256).ct_eq(ft_direct))
  // 384B FE2OS roundtrip and exact slot ordering [c1.c2, c0.c1, c0.c2, c1.c0, c1.c1, c0.c0]
  let encoded = a.to_bytes()
  assert_eq(encoded.length(), 384)
  assert_eq(encoded[0:64], a.c1.c2.to_bytes()[:])
  assert_eq(encoded[64:128], a.c0.c1.to_bytes()[:])
  assert_eq(encoded[128:192], a.c0.c2.to_bytes()[:])
  assert_eq(encoded[192:256], a.c1.c0.to_bytes()[:])
  assert_eq(encoded[256:320], a.c1.c1.to_bytes()[:])
  assert_eq(encoded[320:384], a.c0.c0.to_bytes()[:])
  assert_eq(@field.Fp12::from_bytes_strict(encoded), Some(a))
  // Official e(P2, P1) 384B vector from spec §3.5: verify strict decode -> roundtrip
  // and verify it lies in cyclotomic subgroup (e^{p^6} * e == 1 and cyclotomic_sqr == sqr)
  let e_hex = b"256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f5230167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e90913083105e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf066fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de7869688ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db9277f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a042636a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669"
  let e_bytes = hex_to_bytes(e_hex)
  let e_val = match @field.Fp12::from_bytes_strict(e_bytes) {
    Some(x) => x
    None => abort("valid e(P2, P1) must decode")
  }
  assert_eq(e_val.to_bytes(), e_bytes)
  assert_true(e_val.mul(e_val.conjugate()).is_one())
  assert_true(e_val.cyclotomic_sqr().ct_eq(e_val.sqr()))
  // Reject 384B input with >= p in any 32B coordinate
  let p_bytes = @field.modulus_p.to_be_bytes()
  for slot = 0; slot < 12; slot = slot + 1 {
    let bad = Bytes::makei(384, fn(i) {
      let off = slot * 32
      if i >= off && i < off + 32 {
        p_bytes[i - off]
      } else {
        e_bytes[i]
      }
    })
    assert_eq(@field.Fp12::from_bytes_strict(bad), None)
  }
  assert_eq(@field.Fp12::from_bytes_strict(e_bytes[0:383]), None)
}

///|
test "Official Part 2 g^r == w vector in Fp12 (GB/T 38635.2 Appendix A)" {
  let g_hex = b"4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce000038bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380fa01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a61604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57aaab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"
  let w_hex = b"81377b8fdbc2839b4fa2d0e0f8aa6853bbbe9e9c4099608f8612c6078acd7563815aeba217ad502da0f48704cc73cabb3c06209bd87142e14cbd99e8bca1680f30dadc5cd9e207aee32209f6c3ca3ec0d800a1a42d33c73153ded47c70a39d2e8eaf5d179a1836b359a9d1d9bfc19f2efcdb829328620962bd3fdf15f2567f58a543d25609ae943920679194ed30328bb33fd15660bde485c6b79a7b32b013983f012db04ba59fe88db889321cc2373d4c0c35e84f7ab1ff33679bca575d67654f8624eb435b838cca77b2d0347e65d5e46964412a096f4150d8c5ede5440ddf0656fcb663d24731e80292188a2471b8b68aa993899268499d23c89755a1a89744643cead40f0965f28e1cd2895c3d118e4f65c9a0e3e741b6dd52c0ee2d25f5898d60848026b7efb8fcc1b2442ecf0795f8a81cee99a6248f294c82c90d26bd6a814aaf475f128aef43a128e37f80154ae6cb92cad7d1501bae30f750b3a9bd1f96b08e97997363911314705bfb9a9dbb97f75553ec90fbb2ddae53c8f68e42"
  let r_hex = b"00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe"
  let g = match @field.Fp12::from_bytes_strict(hex_to_bytes(g_hex)) {
    Some(x) => x
    None => abort("valid g")
  }
  let w_expected = match @field.Fp12::from_bytes_strict(hex_to_bytes(w_hex)) {
    Some(x) => x
    None => abort("valid w")
  }
  let r = match @field.U256::from_be_bytes(hex_to_bytes(r_hex)) {
    Some(x) => x
    None => abort("valid r")
  }
  let w_got = g.cyclotomic_pow_u256(r)
  assert_true(w_got.ct_eq(w_expected))
  assert_eq(w_got.to_bytes(), hex_to_bytes(w_hex))
  // Also check e(P2, P1)^N == 1 and g^N == 1
  assert_true(g.cyclotomic_pow_u256(@field.order_n).is_one())
}

///|
test "Carry-overflow > 2^256 boundary tests for Fp, Fn, and Fp2::triple" {
  let max_u256 = @field.U256::from_limbs(
    0xFFFF_FFFF_FFFF_FFFFUL, 0xFFFF_FFFF_FFFF_FFFFUL, 0xFFFF_FFFF_FFFF_FFFFUL, 0xFFFF_FFFF_FFFF_FFFFUL,
  )
  // (2^256 - 1) mod p + 1 == 2^256 mod p == R (which is Fp::from_u256(R))
  let fp_max = @field.Fp::from_u256(max_u256)
  let r_mod_p = @field.U256::from_limbs(
    0x1a9064d81caeba83UL, 0xde0d6cb4e5851124UL, 0x29fc54b00a7138baUL, 0x49bffffffd5c590eUL,
  )
  assert_true(fp_max.add(@field.Fp::one()).ct_eq(@field.Fp::from_u256(r_mod_p)))
  // (p - 1) + (p - 1) overflows 2^256 since p > 2^255; must equal p - 2
  let pm1 = @field.Fp::zero().sub(@field.Fp::one())
  let pm2 = pm1.sub(@field.Fp::one())
  assert_true(pm1.add(pm1).ct_eq(pm2))
  assert_true(pm1.mul(pm1).is_one())
  assert_true(pm2.mul(pm2).ct_eq(@field.Fp::from_u64(4UL)))
  // Same for Fn (N > 2^255)
  let fn_max = @field.Fn::from_u256_mod(max_u256)
  let r_mod_n = @field.U256::from_limbs(
    0x1a911e63296130dbUL, 0xb60d6cb4e7157411UL, 0x29fc54b00a7138bbUL, 0x49bffffffd5c590eUL,
  )
  assert_true(
    fn_max.add(@field.Fn::one()).ct_eq(@field.Fn::from_u256_mod(r_mod_n)),
  )
  let nm1 = @field.Fn::zero().sub(@field.Fn::one())
  let nm2 = nm1.sub(@field.Fn::one())
  assert_true(nm1.add(nm1).ct_eq(nm2))
  assert_true(nm1.mul(nm1).is_one())
  assert_true(nm2.mul(nm2).ct_eq(@field.Fn::from_u64(4UL)))
  // Fp2::triple and ct_select
  let z = @field.Fp2::new(@field.Fp::from_u64(9UL), @field.Fp::from_u64(17UL))
  assert_true(z.triple().ct_eq(z.add(z).add(z)))
  assert_true(
    @field.Fp2::ct_select(z, @field.Fp2::one(), @field.ct_mask(false)).ct_eq(z),
  )
  assert_true(
    @field.Fp2::ct_select(z, @field.Fp2::one(), @field.ct_mask(true)).is_one(),
  )
  // Fp6/Fp12 ct_select
  assert_true(
    @field.Fp6::ct_select(
      @field.Fp6::zero(),
      @field.Fp6::one(),
      @field.ct_mask(true),
    ).is_one(),
  )
  assert_true(
    @field.Fp12::ct_select(
      @field.Fp12::zero(),
      @field.Fp12::one(),
      @field.ct_mask(true),
    ).is_one(),
  )
}

///|
test "Fp::is_zero_mask, Fp2::is_zero_mask, and Fp12::is_in_cyclotomic_subgroup" {
  let all_ones = 0xFFFF_FFFF_FFFF_FFFFUL
  let zero = @field.Fp::zero()
  let one = @field.Fp::one()
  let p_minus_1 = zero.sub(one)
  // Fp::is_zero_mask
  assert_eq(zero.is_zero_mask(), all_ones)
  assert_eq(one.is_zero_mask(), 0UL)
  assert_eq(p_minus_1.is_zero_mask(), 0UL)
  // Fp2::is_zero_mask
  assert_eq(@field.Fp2::zero().is_zero_mask(), all_ones)
  assert_eq(@field.Fp2::new(zero, one).is_zero_mask(), 0UL)
  assert_eq(@field.Fp2::new(one, zero).is_zero_mask(), 0UL)
  assert_eq(@field.Fp2::new(p_minus_1, one).is_zero_mask(), 0UL)
  // Fp12::is_in_cyclotomic_subgroup: positive cases (1 and official e(P2, P1))
  assert_true(@field.Fp12::one().is_in_cyclotomic_subgroup())
  let e_hex = b"256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f5230167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e90913083105e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf066fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de7869688ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db9277f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a042636a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669"
  let e_val = match @field.Fp12::from_bytes_strict(hex_to_bytes(e_hex)) {
    Some(x) => x
    None => abort("valid e(P2, P1) must decode")
  }
  assert_true(e_val.is_in_cyclotomic_subgroup())
  // Negative cases: 0, -1 (which satisfies conjugate * x == 1 but NOT x^{p^4-p^2+1} == 1),
  // and a general non-cyclotomic Fp12 element
  assert_true(!@field.Fp12::zero().is_in_cyclotomic_subgroup())
  assert_true(!@field.Fp12::one().neg().is_in_cyclotomic_subgroup())
  let general = @field.Fp12::new(
    @field.Fp6::new(
      @field.Fp2::new(@field.Fp::from_u64(2UL), @field.Fp::from_u64(3UL)),
      @field.Fp2::new(@field.Fp::from_u64(5UL), @field.Fp::from_u64(7UL)),
      @field.Fp2::new(@field.Fp::from_u64(11UL), @field.Fp::from_u64(13UL)),
    ),
    @field.Fp6::new(
      @field.Fp2::new(@field.Fp::from_u64(17UL), @field.Fp::from_u64(19UL)),
      @field.Fp2::new(@field.Fp::from_u64(23UL), @field.Fp::from_u64(29UL)),
      @field.Fp2::new(@field.Fp::from_u64(31UL), @field.Fp::from_u64(37UL)),
    ),
  )
  assert_true(!general.is_in_cyclotomic_subgroup())
  // Projection (general^{p^6 - 1})^{p^2 + 1} enters G_{Phi_6}(Fp2), while general^{p^6 - 1} alone does not
  let f_norm1 = general.conjugate().mul(general.inv())
  assert_true(f_norm1.conjugate().mul(f_norm1).is_one())
  assert_true(!f_norm1.is_in_cyclotomic_subgroup())
  let f_cyclo = f_norm1.frobenius_p2().mul(f_norm1)
  assert_true(f_cyclo.is_in_cyclotomic_subgroup())
}
