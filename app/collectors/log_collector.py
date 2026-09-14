from pathlib import Path


def read_log_file(file_path: str) -> list[str] : 
    """
    lit fichier log et retourne ses lignes
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Le fichier {file_path} n'existe pas.")

    if not path.is_file():
        raise ValueError(f"{file_path} n'est pas fichier valide")

    with path.open("r", encoding="utf-8", errors="ignore") as file : 
        return file.readlines()


if __name__ == "__main__":
    logs = read_log_file("data/raw/sample.log")

    for line in logs:
        print(line.strip())