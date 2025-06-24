# Copyright 2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit meson

DESCRIPTION="An open-source partial Steam client implementation"
HOMEPAGE="https://github.com/teknology-hub/tek-steamclient"
SRC_URI="
https://github.com/teknology-hub/tek-steamclient/releases/download/v${PV}/${P}.tar.xz
https://github.com/TinyTinni/ValveFileVDF/archive/refs/tags/v1.1.1.tar.gz
"

LICENSE="GPL-3+"
SLOT="0"
KEYWORDS="amd64"

IUSE="+app-manager +cli +cli-dump +content io-uring +nls +qr +s3-client +steampipe zlib-ng"
REQUIRED_USE="
	app-manager? ( content steampipe )
	cli-dump? ( app-manager )
"

COMMON_DEPEND="
	dev-db/sqlite
	dev-libs/openssl
	dev-libs/protobuf[protobuf(+)]
	net-libs/libwebsockets[client,extensions,ssl]
	net-misc/curl[ssl]
	app-manager? (
		io-uring? ( sys-libs/liburing )
	)
	cli? (
		qr? ( media-gfx/qrencode )
	)
	content? ( dev-libs/libzip )
	steampipe? (
		app-arch/xz-utils
		app-arch/zstd
		dev-libs/libzip
	)
	zlib-ng? ( sys-libs/zlib-ng )
	!zlib-ng? ( sys-libs/zlib )
"
DEPEND="
	${COMMON_DEPEND}
	dev-libs/rapidjson
"
BDEPEND="nls? ( sys-devel/gettext )"
RDEPEND="${COMMON_DEPEND}"

src_prepare() {
	default

	mv "${WORKDIR}/ValveFileVDF-1.1.1" "${S}/subprojects/" || die
	cp "${S}/subprojects/packagefiles/ValveFileVDF/meson.build" "${S}/subprojects/ValveFileVDF-1.1.1/" || die
}

src_configure() {
	local emesonargs=(
		$(meson_use app-manager app_manager)
		$(meson_use cli)
		$(meson_use cli-dump cli_dump)
		$(meson_use content)
		$(meson_feature io-uring io_uring)
		$(meson_use nls gettext)
		$(meson_feature qr)
		$(meson_use s3-client s3_client)
		$(meson_use steampipe)
		$(meson_feature zlib-ng zlib_ng)
	)
	meson_src_configure
}
