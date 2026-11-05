<?php
class Repo {
    public function find(Request $request) {
        $name = $request->query->get('name');
        return $this->connection->executeQuery("SELECT * FROM t WHERE name = '" . $name . "'");
    }
}
