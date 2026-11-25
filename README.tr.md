# cargo-cbom

**Rust uygulamanızın TLS bağlantıları kuantum sonrasına hazır mı? `cargo cbom` bunu saniyeler içinde söyler, nedenini açıklar ve düzeltmeyi gösterir.**
Ayrıca [CycloneDX 1.6](https://cyclonedx.org/capabilities/cbom/) formatında bir Kriptografik Malzeme Listesi (CBOM) üretir.

[English README](README.md)

```text
$ cargo cbom
cargo-cbom 0.1.0 · post-quantum readiness of my-api 0.1.0
128 packages scanned (normal dependencies, target x86_64-unknown-linux-gnu) · 85 rules

TLS key exchange
  ! depends            rustls 0.23.46  aws-lc-rs provider, post-quantum not preferred
```

## Neden

"Şimdi topla, sonra çöz" saldırıları yüzünden ilk taşınması gereken şey anahtar
değişimi. Rust'ta bu genellikle rustls demek. rustls 0.23.27 ve sonrası hibrit
`X25519MLKEM768` grubunu varsayılan olarak tercih eder, ama iki koşulla: **aws-lc-rs**
altyapısı kullanılıyor olmalı ve **`prefer-post-quantum`** özelliği açık olmalı. Çoğu
proje rustls'u doğrudan kullanmaz; aradaki paketler de genellikle rustls'un varsayılan
özelliklerini kapatır.

cargo-cbom 0.1.0 ile 24 Kasım 2026'da kontrol edildi (her paket varsayılan özellikleriyle):

| Bağımlılığınız | rustls altyapısı | `prefer-post-quantum` | Sonuç |
|---|---|---|---|
| `rustls` 0.23.46 | aws-lc-rs | açık | ✓ hibrit, X25519MLKEM768 önce sunuluyor |
| `reqwest` 0.13.5 | aws-lc-rs | kapalı | ! istemci klasik X25519 ile başlıyor |
| `hyper-rustls` 0.27.10 | aws-lc-rs | kapalı | ! istemci klasik X25519 ile başlıyor |
| `tokio-rustls` 0.26.6 | aws-lc-rs | kapalı | ! istemci klasik X25519 ile başlıyor |
| `ureq` 3.5.2 | ring | yok | ✗ kuantum sonrası anahtar değişimi yok |
| `reqwest` 0.12.28 + `rustls-tls` | ring | yok | ✗ kuantum sonrası anahtar değişimi yok |

`Cargo.lock` hangi özelliklerin açık olduğunu kaydetmez; bu yüzden paket adına bakan
bir araç bu durumları ayırt edemez. cargo-cbom, `cargo metadata` ile **çözümlenmiş
bağımlılık grafiğini ve Cargo'nun gerçekten açtığı özellikleri** okur.

reqwest için düzeltme, kendi `Cargo.toml` dosyanıza eklenecek tek satır:

```toml
rustls = { version = "0.23.27", default-features = false, features = ["prefer-post-quantum"] }
```

```text
$ cargo cbom
TLS key exchange
  ✓ hybrid             rustls 0.23.46  aws-lc-rs provider, post-quantum preferred
```

`ureq` 3 kullanıyorsanız, ureq başka bir altyapı kurulmadıkça ring'i seçtiği için,
programın başında aws-lc-rs'i de kurun:

```rust
rustls::crypto::aws_lc_rs::default_provider().install_default().unwrap();
```

Çalışan bir istemcinin gerçekte neyi seçtiğini görmek için onunla
`https://www.cloudflare.com/cdn-cgi/trace` adresini çağırıp `kex=` satırına bakın.

## Kurulum ve kullanım

```sh
cargo install cargo-cbom --locked            # Rust 1.86 veya üstü
cargo cbom                                   # mevcut proje için rapor
cargo cbom --format cbom --output cbom.json  # CycloneDX 1.6 CBOM
cargo cbom --fail-on vulnerable              # kuantuma karşı savunmasız bulgu varsa çıkış kodu 1
cargo cbom --include-dev --include-build     # dev/build bağımlılıklarını da tara
cargo cbom --all-targets                     # sadece bu makine değil, tüm platformlar
cargo cbom --list-rules
```

Çıkış kodları: `0` sorun yok, `1` `--fail-on` ile eşleşen bulgu var, `2` hata.

CI'da kullanmak, durum (status) tablosu, kuralların nasıl çalıştığı ve sınırlamalar
için [İngilizce README](README.md)'ye bakın.

## Sınırlamalar

- Araç, kodunuzun hangi fonksiyonu çağırdığını değil, nelerin derlendiğini raporlar.
- İki rustls altyapısı birden derlenmişse hangisinin kullanılacağı çalışma anında
  belirlenir; cargo-cbom tahmin etmek yerine bunu açıkça yazar.
- Bir güvenlik açığı veritabanı değildir; `cargo audit` veya `cargo deny` kullanmaya
  devam edin.

## Katkı

En kolay katkı yeni bir kural eklemektir; bkz. [CONTRIBUTING.md](CONTRIBUTING.md).

## Lisans

[Apache 2.0](LICENSE-APACHE) veya [MIT](LICENSE-MIT), tercihinize göre.
