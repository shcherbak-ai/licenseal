defmodule Web.MixProject do
  use Mix.Project

  def project do
    [
      app: :web,
      version: "0.1.0",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:core, in_umbrella: true},
      {:phoenix, "~> 1.7"}
    ]
  end
end
