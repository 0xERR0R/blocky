package web

// IndexTmpl html template for the start page
const IndexTmpl = `<!DOCTYPE html>
<html>
	<head>
		<title>blocky</title>
	</head>
	<body>
		<h1>blocky</h1>
		<ul>
		{{range .}}
			<li><a href="{{.URL}}">{{.Title}}</a></li>
		{{end}}
		</ul>
		</body>
	</html>`
