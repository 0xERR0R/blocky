{
  outputs = { self, nixpkgs }:
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      packages.x86_64-linux = rec {
        default = blocky;

        blocky = pkgs.hello;
      };

      devShells.x86_64-linux.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          # TODO: trim
          # delve
          # clang
          # gcc
          ginkgo
          go
          # go-outline
          # golangci-lint
          # gofumpt
          # gomodifytags
          # gopls
          # gopkgs
          # gotests
          # impl
        ];
      };
    };
}
