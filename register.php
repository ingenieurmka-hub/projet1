<?php
declare(strict_types=1);
session_start();
include 'config.php'; // doit définir $conn (mysqli)

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$conn->set_charset('utf8mb4');

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

/* Normalise un numéro RDC en +243XXXXXXXXX ; retourne null si invalide */
function normaliser_telephone(string $tel): ?string {
    $d = preg_replace('/\D+/', '', $tel);
    if (preg_match('/^243(\d{9})$/', $d, $m)) return '+243' . $m[1];
    if (preg_match('/^0(\d{9})$/', $d, $m))   return '+243' . $m[1];
    if (preg_match('/^(\d{9})$/', $d, $m))    return '+243' . $m[1];
    return null;
}

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));

$erreur = '';
$nom = '';
$telephone = '';
$succes = isset($_GET['ok']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nom       = trim(preg_replace('/\s+/', ' ', strip_tags($_POST['nom'] ?? '')));
    $telephone = trim($_POST['telephone'] ?? '');
    $mdp       = $_POST['mot_de_passe'] ?? '';
    $mdp2      = $_POST['mot_de_passe2'] ?? '';
    $tel       = normaliser_telephone($telephone);

    if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        $erreur = "Session expirée. Rechargez la page et réessayez.";
    } elseif (!empty($_POST['website'])) {
        $erreur = "Requête invalide."; // champ piège pour les robots
    } elseif ($nom === '' || $telephone === '' || $mdp === '') {
        $erreur = "Veuillez remplir tous les champs.";
    } elseif (mb_strlen($nom) < 3 || mb_strlen($nom) > 100) {
        $erreur = "Le nom doit contenir entre 3 et 100 caractères.";
    } elseif ($tel === null) {
        $erreur = "Numéro invalide. Exemple : 0812345678 ou +243812345678.";
    } elseif (strlen($mdp) < 8) {
        $erreur = "Le mot de passe doit contenir au moins 8 caractères.";
    } elseif ($mdp !== $mdp2) {
        $erreur = "Les deux mots de passe ne correspondent pas.";
    } elseif (empty($_POST['accord'])) {
        $erreur = "Vous devez accepter les conditions et la politique de confidentialité.";
    } else {
        try {
            $chk = $conn->prepare("SELECT 1 FROM couac WHERE telephone = ? LIMIT 1");
            $chk->bind_param("s", $tel);
            $chk->execute();
            $existe = $chk->get_result()->num_rows > 0;
            $chk->close();

            if ($existe) {
                $erreur = "Ce numéro est déjà inscrit. Connectez-vous.";
            } else {
                $hash = password_hash($mdp, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO couac (nom, telephone, mot_de_passe) VALUES (?, ?, ?)");
                $stmt->bind_param("sss", $nom, $tel, $hash);
                $stmt->execute();
                $stmt->close();
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                header('Location: register.php?ok=1'); // évite le renvoi du formulaire au rafraîchissement
                exit;
            }
        } catch (mysqli_sql_exception $ex) {
            error_log('register.php : ' . $ex->getMessage());
            $erreur = ($ex->getCode() === 1062)
                ? "Ce numéro est déjà inscrit. Connectez-vous."
                : "Une erreur est survenue. Réessayez dans un instant.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Créer un compte – TechnoAcademy</title>
<meta name="robots" content="noindex">
<link rel="icon" href="MEDIA/logo.jpeg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--primary:#0f172a;--blue:#2563eb;--cta:#c2410c;--cta-h:#9a3412;--wa:#075E54;--text:#334155;--muted:#64748b;--bg:#f8fafc;--card:#fff;--border:#cbd5e1}
@media(prefers-color-scheme:dark){:root{--primary:#f8fafc;--blue:#60a5fa;--text:#cbd5e1;--muted:#94a3b8;--bg:#0f172a;--card:#1e293b;--border:#475569}}
*{box-sizing:border-box;margin:0;padding:0;font-family:'Inter',system-ui,-apple-system,sans-serif}
body{background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px 16px;line-height:1.6}
:focus-visible{outline:3px solid var(--blue);outline-offset:2px}
.box{background:var(--card);width:100%;max-width:440px;border:1px solid var(--border);border-radius:20px;padding:32px 28px;box-shadow:0 8px 24px rgba(0,0,0,.08)}
.logo{display:block;margin:0 auto 20px;height:44px;width:auto}
h1{font-size:1.6rem;font-weight:800;color:var(--primary);line-height:1.3;margin-bottom:6px}
.sub{font-size:14px;color:var(--muted);margin-bottom:22px}
.badge{display:inline-block;background:#166534;color:#fff;font-size:12px;font-weight:700;padding:4px 12px;border-radius:50px;margin-bottom:12px}
label{display:block;font-weight:600;font-size:14px;color:var(--primary);margin-bottom:6px}
.field{margin-bottom:16px}
input[type=text],input[type=tel],input[type=password]{width:100%;padding:14px 16px;border:1px solid var(--border);border-radius:12px;font-size:16px;background:var(--bg);color:var(--text)}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(37,99,235,.18);outline:none}
.hint{font-size:12px;color:var(--muted);margin-top:4px}
.check{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:var(--muted);margin-bottom:16px}
.check input{margin-top:4px;width:16px;height:16px;flex:none}
.check label{font-weight:400;color:var(--muted);margin:0;font-size:13px}
a{color:var(--blue)}
.btn{display:flex;align-items:center;justify-content:center;width:100%;padding:15px;background:var(--cta);border:2px solid var(--cta);color:#fff;font-size:15px;font-weight:700;border-radius:50px;cursor:pointer;text-decoration:none}
.btn:hover{background:var(--cta-h);border-color:var(--cta-h)}
.btn.wa{background:var(--wa);border-color:var(--wa)}
.btn.line{background:transparent;color:var(--text);border-color:var(--border)}
.btn.line:hover{background:rgba(100,116,139,.15)}
.stack{display:grid;gap:12px}
.alert{padding:12px 14px;border-radius:10px;margin-bottom:18px;font-size:14px}
.error{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
.success{background:#dcfce7;color:#166534;border:1px solid #86efac}
.foot{margin-top:18px;text-align:center;font-size:14px}
.hp{position:absolute;left:-9999px}
</style>
</head>
<body>
<div class="box">
  <img class="logo" src="MEDIA/logo.jpeg" alt="TechnoAcademy" width="160" height="44">

<?php if ($succes): ?>
  <h1>Compte créé avec succès</h1>
  <p class="sub">Bienvenue chez TechnoAcademy. Choisissez maintenant votre formation et réservez votre place pour la prochaine session.</p>
  <div class="stack">
    <a class="btn" href="login.php">Se connecter</a>
    <a class="btn line" href="formations.html">Choisir ma formation</a>
    <a class="btn wa" href="https://wa.me/243819928332?text=Bonjour%20TechnoAcademy%2C%20je%20viens%20de%20cr%C3%A9er%20mon%20compte%20et%20je%20souhaite%20choisir%20ma%20formation." target="_blank" rel="noopener">Continuer sur WhatsApp</a>
  </div>

<?php else: ?>
  <span class="badge">Création de compte gratuite</span>
  <h1>Créer un compte</h1>
  <p class="sub">Rejoignez-nous en moins de 2 minutes. La création du compte est gratuite : vous ne payez que la formation que vous choisissez.</p>

  <?php if ($erreur !== ''): ?>
    <div class="alert error" role="alert"><?= e($erreur) ?></div>
  <?php endif; ?>

  <form method="POST" action="register.php" novalidate>
    <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
    <div class="hp" aria-hidden="true"><label>Ne pas remplir <input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>

    <div class="field">
      <label for="nom">Nom complet</label>
      <input type="text" id="nom" name="nom" value="<?= e($nom) ?>" autocomplete="name" maxlength="100" required>
    </div>
    <div class="field">
      <label for="tel">Numéro WhatsApp</label>
      <input type="tel" id="tel" name="telephone" value="<?= e($telephone) ?>" inputmode="tel" autocomplete="tel" placeholder="0812345678" required>
      <p class="hint">Exemple : 0812345678 ou +243812345678</p>
    </div>
    <div class="field">
      <label for="password">Mot de passe</label>
      <input type="password" id="password" name="mot_de_passe" autocomplete="new-password" minlength="8" required>
      <p class="hint">8 caractères minimum.</p>
    </div>
    <div class="field">
      <label for="password2">Confirmer le mot de passe</label>
      <input type="password" id="password2" name="mot_de_passe2" autocomplete="new-password" minlength="8" required>
    </div>
    <div class="check" style="margin-top:-6px">
      <input type="checkbox" id="show"><label for="show">Afficher les mots de passe</label>
    </div>
    <div class="check">
      <input type="checkbox" id="accord" name="accord" value="1" required>
      <label for="accord">J'accepte les <a href="conditions.html" target="_blank" rel="noopener">conditions d'inscription</a> et la <a href="confidentialite.html" target="_blank" rel="noopener">politique de confidentialité</a>.</label>
    </div>
    <button type="submit" class="btn">Créer mon compte gratuitement</button>
  </form>

  <p class="foot">Déjà inscrit ? <a href="login.php">Se connecter</a> · <a href="index.html">Retour à l'accueil</a></p>
<?php endif; ?>
</div>

<script>
const show = document.getElementById('show');
if (show) show.addEventListener('change', () => {
  ['password', 'password2'].forEach(id => { document.getElementById(id).type = show.checked ? 'text' : 'password'; });
});
</script>
</body>
</html>
