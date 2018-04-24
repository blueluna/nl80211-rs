ARM_TRIPLET=armv7-unknown-linux-musleabihf

host:
	cargo build --release

arm:
	cargo build  --release --target=$(ARM_TRIPLET)
	stat target/$(ARM_TRIPLET)/release/nl80211_example | sed -n -e 's/Size:\s\+\([[:digit:]]\+\).*/\1/p'
	cp target/$(ARM_TRIPLET)/release/nl80211_example target/$(ARM_TRIPLET)/release/nl80211_example.orig
	/usr/local/kreatv/toolchain/bcm15/2.2.7/bin/arm-kreatv-linux-gnueabihf-strip target/$(ARM_TRIPLET)/release/nl80211_example
	stat target/$(ARM_TRIPLET)/release/nl80211_example | sed -n -e 's/Size:\s\+\([[:digit:]]\+\).*/\1/p'

PHONY: host arm
