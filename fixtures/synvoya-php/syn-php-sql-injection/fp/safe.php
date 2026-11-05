<?php
$id = (int) $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
mysqli_query($conn, "SELECT * FROM users WHERE id = " . intval($_GET['id']));
$stmt = $pdo->prepare("SELECT * FROM posts WHERE slug = ?");
$stmt->execute([$_POST['slug']]);
$name = mysqli_real_escape_string($conn, $_GET['name']);
mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
function wp_lookup() {
    global $wpdb;
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM t WHERE status = %s", $_GET['status'] ) );
}
function wp_ids() {
    global $wpdb;
    $ids = implode( ',', array_map( 'absint', $_POST['ids'] ) );
    return $wpdb->query( "DELETE FROM t WHERE id IN ($ids)" );
}
class C {
    public function index(Request $request) {
        DB::select('SELECT * FROM items WHERE name = ?', [$request->input('q')]);
        return DB::table('t')->whereRaw('team = ?', [$request->get('team')])->get();
    }
}
$cache->query($_GET['q']);
$total = count($_GET);
mysqli_query($conn, "SELECT * FROM log LIMIT " . $total);
