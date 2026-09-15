from pathlib import Path


def read_log_file(file_path: str) -> list[str] : 
    """
    Lit un fichier de logs et retourne son contenu ligne par ligne.

    Paramètre
    ---------
    file_path : str
        Chemin vers le fichier de logs.

    Retour
    ------
    list[str]
        Liste contenant toutes les lignes du fichier.

    Exceptions
    ----------
    FileNotFoundError
        Si le fichier n'existe pas.

    ValueError
        Si le chemin fourni ne correspond pas à un fichier.
    """
    path = Path(file_path)

#Vérifie que le chemin existe réellement
    if not path.exists():
        raise FileNotFoundError(f"Le fichier {file_path} n'existe pas.")
#vérifie que le chemin pointe vers un fichier et non vers un dossier
    if not path.is_file():
        raise ValueError(f"{file_path} n'est pas fichier valide")
#ouverture du fichier en lecture, encoding='utf-8' permet de lire les caractères UTF-8
#errors='ignore' permet d'éviter un crash si certains caractères du fichier sont mal encodés

    with path.open("r", encoding="utf-8", errors="ignore") as file : 
        return file.readlines()


if __name__ == "__main__":
    #ce bloc est exécuté uniquement si le fichier est lancé directement avec python
    test_file = "data/raw/sample.log"

    try:
        logs = read_log_file(test_file)
        print(f"{len(logs)} lignes trouvées.\n")

        for line in logs:
                print(line.strip())

    except (FileNotFoundError, ValueError) as error:
         #affichage des erreurs
         print(f"Erreur : {error}")



    