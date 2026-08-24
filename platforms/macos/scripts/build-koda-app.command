#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h:h:h}"
PACKAGING_DIR="${SCRIPT_DIR:h}/packaging"

APP_NAME="${APP_NAME:-KODA}"
VERSION="${VERSION:-0.1.0}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
BUNDLE_ID="${BUNDLE_ID:-com.jhnykor.koda}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SKIP_DEPENDENCY_INSTALL="${SKIP_DEPENDENCY_INSTALL:-0}"
CODE_SIGN_IDENTITY="${CODE_SIGN_IDENTITY:-}"
INSTALLER_SIGN_IDENTITY="${INSTALLER_SIGN_IDENTITY:-}"

BUILD_ROOT="$REPO_ROOT/.build/macos-koda"
VENV_DIR="$BUILD_ROOT/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"
DIST_DIR="$REPO_ROOT/dist/macos"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
PKG_UNSIGNED="$DIST_DIR/$APP_NAME-$VERSION-unsigned.pkg"
PKG_SIGNED="$DIST_DIR/$APP_NAME-$VERSION.pkg"
ENTRY_POINT="$REPO_ROOT/platforms/macos/scripts/koda-browser-app.py"
ICON_FILE="$PACKAGING_DIR/assets/KODA.icns"
ENTITLEMENTS="$PACKAGING_DIR/KODA.entitlements"

set_plist_string() {
  local plist="$1"
  local key="$2"
  local value="$3"

  if ! /usr/libexec/PlistBuddy -c "Set :$key $value" "$plist" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Add :$key string $value" "$plist"
  fi
}

if [[ ! -f "$ENTRY_POINT" ]]; then
  echo "Missing entry point: $ENTRY_POINT"
  exit 1
fi
if [[ ! -f "$ICON_FILE" ]]; then
  echo "Missing app icon: $ICON_FILE"
  exit 1
fi
if [[ ! -f "$ENTITLEMENTS" ]]; then
  echo "Missing entitlements: $ENTITLEMENTS"
  exit 1
fi

mkdir -p "$BUILD_ROOT" "$DIST_DIR"

if [[ ! -x "$VENV_PYTHON" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

if [[ "$SKIP_DEPENDENCY_INSTALL" != "1" ]]; then
  "$VENV_PYTHON" -m pip install --upgrade pip pyinstaller
fi

rm -rf "$APP_BUNDLE" "$BUILD_ROOT/pyinstaller-work" "$BUILD_ROOT/pyinstaller-spec"

"$VENV_PYTHON" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name "$APP_NAME" \
  --icon "$ICON_FILE" \
  --distpath "$DIST_DIR" \
  --workpath "$BUILD_ROOT/pyinstaller-work" \
  --specpath "$BUILD_ROOT/pyinstaller-spec" \
  --paths "$REPO_ROOT/platforms/shared/python" \
  --collect-submodules security_scanner \
  --hidden-import tkinter \
  --hidden-import tkinter.filedialog \
  --hidden-import tkinter.messagebox \
  "$ENTRY_POINT"

INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"
if [[ ! -f "$INFO_PLIST" ]]; then
  echo "PyInstaller did not create Info.plist: $INFO_PLIST"
  exit 1
fi

set_plist_string "$INFO_PLIST" CFBundleIdentifier "$BUNDLE_ID"
set_plist_string "$INFO_PLIST" CFBundleName "$APP_NAME"
set_plist_string "$INFO_PLIST" CFBundleDisplayName "$APP_NAME"
set_plist_string "$INFO_PLIST" CFBundleShortVersionString "$VERSION"
set_plist_string "$INFO_PLIST" CFBundleVersion "$BUILD_NUMBER"
set_plist_string "$INFO_PLIST" LSApplicationCategoryType "public.app-category.developer-tools"
set_plist_string "$INFO_PLIST" NSHumanReadableCopyright "Copyright © 2026 KODA"

if [[ -n "$CODE_SIGN_IDENTITY" ]]; then
  codesign --force --deep --options runtime --entitlements "$ENTITLEMENTS" --sign "$CODE_SIGN_IDENTITY" "$APP_BUNDLE"
else
  echo "CODE_SIGN_IDENTITY is not set; leaving $APP_BUNDLE unsigned for local testing."
fi

rm -f "$PKG_UNSIGNED" "$PKG_SIGNED"
if [[ -n "$INSTALLER_SIGN_IDENTITY" ]]; then
  productbuild --component "$APP_BUNDLE" /Applications --sign "$INSTALLER_SIGN_IDENTITY" "$PKG_SIGNED"
  echo "Signed package: $PKG_SIGNED"
else
  productbuild --component "$APP_BUNDLE" /Applications "$PKG_UNSIGNED"
  echo "Unsigned package: $PKG_UNSIGNED"
fi

echo "App bundle: $APP_BUNDLE"
echo "Bundle ID: $BUNDLE_ID"
