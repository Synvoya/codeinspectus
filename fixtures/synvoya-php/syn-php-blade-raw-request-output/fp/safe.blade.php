<h1>Results for {{ request('q') }}</h1>
<div>{!! $post->rendered_html !!}</div>
{!! csrf_field() !!}
<input value="{{ old('email') }}">
