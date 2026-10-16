{
  mkApplication,
  pythonSet,
  venv,
  ...
}:
mkApplication {
  inherit venv;
  package = pythonSet.cwrunix-bot;
}
