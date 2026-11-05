<?php
class ReportController {
    public function index(Request $request) {
        $sort = $request->input('sort');
        return DB::table('reports')->orderByRaw($sort)->get();
    }
    public function search(Request $request) {
        return \DB::select("SELECT * FROM items WHERE name LIKE '%" . $request->query('q') . "%'");
    }
    public function count(Request $request) {
        return User::query()->whereRaw("team = " . $request->get('team'))->count();
    }
}
