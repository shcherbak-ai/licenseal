defmodule Simple.MixProject do
  use Mix.Project

  def project do
    [
      app: :simple,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps(),
      package: package()
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.10"},
      {:ecto_sql, "~> 3.10"},
      {:jason, ">= 1.0.0"},
      # Dev / test tooling — only: restricts to non-prod envs.
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.30", only: :dev, runtime: false},
      # Off-registry sources — flagged off-registry, resolver short-circuits.
      {:my_fork, github: "me/my_fork", branch: "main"},
      {:vendored, path: "../vendored"}
    ]
  end

  defp package do
    [
      licenses: ["MIT", "Apache-2.0"],
      links: %{"GitHub" => "https://github.com/me/simple"}
    ]
  end
end
