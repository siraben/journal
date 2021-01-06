{ pkgs ? import <nixpkgs> { }}:
with pkgs;

stdenv.mkDerivation {
  name = "journal";
  src = lib.cleanSource ./src;
  buildInputs = [ libsodium boehmgc ];
  buildPhase = ''
    $CC -O2 -o journal journal.c -lsodium -lgc
  '';
  installPhase = ''
    install -Dm755 journal -t $out/bin
  '';
}
