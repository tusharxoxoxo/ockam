defmodule Ockam.MixProject do
  use Mix.Project

  @version "0.1.0"

  @elixir_requirement "~> 1.10"

  @ockam_github_repo "https://github.com/build-trust/ockam"
  @ockam_github_repo_path "implementations/elixir/ockam/ockam"

  def project do
    [
      app: :ockam,
      version: @version,
      elixir: @elixir_requirement,
      consolidate_protocols: Mix.env() != :test,
      elixirc_options: [warnings_as_errors: true],
      deps: deps(),
      aliases: aliases(),

      # lint
      dialyzer: [
        flags: [:error_handling],
        plt_add_apps: [:bare, :ranch, :ssl, :telemetry, :ockam_vault_software]
      ],

      # test
      test_coverage: [output: "_build/cover"],
      preferred_cli_env: ["test.cover": :test],
      elixirc_paths: elixirc_paths(Mix.env()),

      # hex
      description: "A collection of tools for building connected systems that you can trust.",
      package: package(),

      # docs
      name: "Ockam",
      docs: docs()
    ]
  end

  # mix help compile.app for more
  def application do
    [
      mod: {Ockam, []},
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:bare, "~> 0.1.1"},
      {:cbor, "~> 1.0.0"},
      {:ockam_typed_cbor, path: "../ockam_typed_cbor"},
      {:gen_state_machine, "~> 3.0"},
      {:telemetry, "~> 1.0", optional: true},
      {:ranch, "~> 2.1", optional: true},
      {:ex_doc, "~> 0.25", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.1", only: [:dev], runtime: false},
      {:ockly, path: "../ockly"}
    ]
  end

  # used by hex
  defp package do
    [
      links: %{"GitHub" => @ockam_github_repo},
      licenses: ["Apache-2.0"]
    ]
  end

  # used by ex_doc
  defp docs do
    [
      main: "Ockam",
      source_url_pattern:
        "#{@ockam_github_repo}/blob/v#{@version}/#{@ockam_github_repo_path}/%{path}#L%{line}"
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/ockam/helpers"]
  defp elixirc_paths(_), do: ["lib"]

  defp aliases do
    [
      credo: "credo --strict",
      docs: "docs --output _build/docs --formatter html",
      "test.cover": "test --cover",
      "lint.format": "format --check-formatted",
      "lint.credo": "credo --strict",
      "lint.dialyzer": "dialyzer --format dialyxir",
      lint: ["lint.format", "lint.credo"]
    ]
  end
end
