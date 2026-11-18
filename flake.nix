{
  description = "Development tools for DotENV by NostraDavid";

  # Nixpkgs 26.05 retains Intel macOS support.
  inputs.nixpkgs.url = "github:nixos/nixpkgs/da6dc0e7b26060f2f71ce3ef7088fb56ee44fa36";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShellNoCC {
            shellHook =
              import
                (builtins.fetchurl {
                  url = "https://raw.githubusercontent.com/NostraDavid/nixcfg/cb2423e55f4a7ee010d33a649ddf0488338baa42/nix/system-tools.nix";
                  sha256 = "7d2abe646d9389e296c5e1cafa0b63dd52e9821c58037d9dd8faef90124104e2";
                })
                pkgs
                [
                  "git"
                  "just"
                  "nodejs_24"
                  "dprint"
                  "oxlint"
                  "prek"
                  "nixfmt"
                  "statix"
                  "deadnix"
                  "actionlint"
                  "shellcheck"
                ];
          };
        }
      );
      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
