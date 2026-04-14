<?php
	include_once 'header.php';
	if (!isset($_SESSION['u_id'])) {
	header("Location: home.php");
	exit(); 
	} else {
		$user_id = $_SESSION['u_id'];
		$user_uid = $_SESSION['u_uid'];
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 2</h2>
				<?php
				if (isset($_GET['FileToView'])) {
					$fileName = basename($_GET['FileToView']);
					$safePath = "document/" . $fileName;

					if (file_exists($safePath)) {
                		$FileData = file_get_contents($safePath);
						echo "<pre>" . htmlspecialchars($FileData) . "</pre>";
					} else {
						echo "Access denied or file not found.";
					}
				}
				?>
        </section>

<?php
	include_once 'footer.php';
?>