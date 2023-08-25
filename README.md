# SharpShellPipe

## Project Description

![Image](Assets/image.png)

This lightweight C# application serves as a demonstration of how simple it is to interactively access a remote system's shell via named pipes using the SMB protocol. It includes an optional encryption layer leveraging AES GCM, utilizing a shared passphrase between both the server and the client. If you're interested in an example that employs both AES GCM and RSA for additional security, consider checking out another one of my projects, [SharpFtpC2](https://github.com/DarkCoderSc/SharpFtpC2). Implementing that security layer into this project would also be relatively straightforward.

Exercise caution if you decide to use this project in a production environment; it was not designed for such use. Proceed at your own risk. The primary aim of this project is to illustrate a well-known network evasion detection technique that will soon be featured on the [Unprotect Project](https://unprotect.it/) website.

## Usage

### Server

`SharpShellPipe.exe`

This is the computer you wish to access to.

### Client

`SharpShellPipe.exe --client`

You will be prompted to enter the name of the computer you wish to connect to the one hosting the **SharpShellPipe** Server. To connect to the local machine, you can either enter `.` or simply press the Enter key.

---

# Disclaimer

🇺🇸 All source code and projects shared on this Github account by Jean-Pierre LESUEUR and his company, PHROZEN SAS, are provided "as is" without warranty of any kind, either expressed or implied. The user of this code assumes all responsibility for any issues or legal liabilities that may arise from the use, misuse, or distribution of this code. The user of this code also agrees to release Jean-Pierre LESUEUR and PHROZEN SAS from any and all liability for any damages or losses that may result from the use, misuse, or distribution of this code.

By using this code, the user agrees to indemnify and hold Jean-Pierre LESUEUR and PHROZEN SAS harmless from any and all claims, liabilities, costs, and expenses arising from the use, misuse, or distribution of this code. The user also agrees not to hold Jean-Pierre LESUEUR or PHROZEN SAS responsible for any errors or omissions in the code, and to take full responsibility for ensuring that the code meets the user's needs.

This disclaimer is subject to change without notice, and the user is responsible for checking for updates. If the user does not agree to the terms of this disclaimer, they should not use this code.

---

🇫🇷 Tout les codes sources et les projets partagés sur ce compte Github par Jean-Pierre LESUEUR et sa société, PHROZEN SAS, sont fournis "tels quels" sans aucune garantie, expresse ou implicite. L'utilisateur de ce code assume toute responsabilité pour les problèmes ou les responsabilités juridiques qui pourraient résulter de l'utilisation, de l'utilisation abusive ou de la diffusion de ce code. L'utilisateur de ce code accepte également de libérer Jean-Pierre LESUEUR et PHROZEN SAS de toute responsabilité pour tous dommages ou pertes pouvant résulter de l'utilisation, de l'utilisation abusive ou de la diffusion de ce code.

En utilisant ce code, l'utilisateur accepte de garantir et de dégager Jean-Pierre LESUEUR et PHROZEN SAS de toutes réclamations, responsabilités, coûts et dépenses résultant de l'utilisation, de l'utilisation abusive ou de la diffusion de ce code. L'utilisateur accepte également de ne pas tenir Jean-Pierre LESUEUR ou PHROZEN SAS responsable des erreurs ou omissions dans le code et de prendre l'entière responsabilité de s'assurer que le code répond aux besoins de l'utilisateur.

Cette clause de non-responsabilité est sujette à modification sans préavis et l'utilisateur est responsable de vérifier les mises à jour. Si l'utilisateur n'accepte pas les termes de cette clause de non-responsabilité, il ne doit pas utiliser ce code.