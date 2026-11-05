<?php
// Re-triage A1-A4: allow-listed or numeric values are not injectable.
function a1($wpdb) {
  $order = in_array($_GET['order'], ['ASC', 'DESC'], true) ? $_GET['order'] : 'ASC';
  return $wpdb->get_results("SELECT * FROM t ORDER BY id $order");
}
function a2($db) {
  $col = $_GET['sort'];
  if (!in_array($col, ['name', 'date'], true)) { $col = 'name'; }
  return $db->query("SELECT * FROM t ORDER BY " . $col);
}
function a3($wpdb) {
  return $wpdb->query(sprintf("DELETE FROM t WHERE id = %d", $_GET['id']));
}
function a4($wpdb) {
  $ids = implode(',', array_map('intval', $_POST['ids']));
  return $wpdb->query("DELETE FROM t WHERE id IN ($ids)");
}
function a5($db) {
  $limit = (int) $_GET['limit'];
  return $db->query(sprintf("SELECT * FROM t LIMIT %d OFFSET %u", $limit, intval($_GET['offset'])));
}
