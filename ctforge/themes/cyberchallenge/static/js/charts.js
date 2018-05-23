var defaultGraphSettings = {
    "lineThickness": 3,
    "type": "line"
};

var defaultChartSettings = {
    "categoryAxis": {
        "minPeriod": "ss",
        "parseDates": true
    },
    "categoryField": "date",
    "chartCursor": {
        "categoryBalloonDateFormat": "JJ:NN:SS",
        "categoryBalloonText": "[[category]]",
        "enabled": true
    },
    "chartScrollbar": {
        "dragIcon": "dragIconRectSmall",
        "enabled": true,
        "scrollbarHeight": 10,
        "dragIconHeight": 22,
        "dragIconWidth": 22
    },
    "dataDateFormat": "YYYY-MM-DD HH:NN:SS",
    "fontFamily": "Monda",
    "fontSize": 14,
    "legend": {
        "color": "#D4D4D4",
        "enabled": true,
        "useGraphSettings": true
    },
    "theme": "dark",
    "titles": [{
        "size": 15,
        "text": ""
    }],
    "type": "serial",
    "valueAxes": [{
        "title": ""
    }]
};

function makeChart(divId, data, populate) {
    var chart = $.extend(true, {}, defaultChartSettings);
    populate(chart, data);
    AmCharts.makeChart(divId, chart);
}

function compareByDate(o1, o2) {
    return o1.date - o2.date;
}

function usersChart(chart, users) {
    chart.titles[0].text = "Players (top 10)";
    chart.valueAxes[0].title = "Points";
    chart.graphs = [];
    chart.dataProvider = [];

    if (users.length === 0) return;

    var i, j, s;
    var challs = Object.keys(users[0].challenges);
    for (i = 0; i < Math.min(users.length, 10); i++) {
        /* Create a new graph for the user. */
        var g = $.extend(true, {}, defaultGraphSettings);
        g.balloonText = "[[title]] [[value]]pts";
        g.title = g.valueField = users[i].user;
        chart.graphs.push(g);

        /* Compute cumulative scores based on the user's submissions. */
        var submissions = [];
        for (j = 0; j < challs.length; j++) {
            var c = users[i].challenges[challs[j]];
            if (c.timestamp !== null) {
                submissions.push({ date: new Date(c.timestamp), points: c.points });
            }
        }
        submissions.sort(compareByDate);
        var points = 0;
        for (j = 0; j < submissions.length; j++) {
            s = { date: submissions[j].date };
            points += submissions[j].points;
            s[g.valueField] = points;
            chart.dataProvider.push(s);
        }
    }
    chart.dataProvider.sort(compareByDate);

    /* For each user, add a fake point in the corresponding graph dated as the last submission.
     * In this way all graphs span the entire chart area. */
    var lastSubmission = chart.dataProvider[chart.dataProvider.length - 1].date;
    for (i = 0; i < users.length; i++) {
        s = { date: lastSubmission };
        s[users[i].user] = users[i].points;
        chart.dataProvider.push(s);
    }
}

function challengesChart(chart, users) {
    chart.titles[0].text = "Challenges";
    chart.valueAxes[0].title = "Solvers";
    chart.graphs = [];
    chart.dataProvider = [];

    if (users.length === 0) return;

    var i, j, s;
    var challs = Object.keys(users[0].challenges);

    /* Get all users submissions, sorted by date. */
    var submissions = [];
    for (i = 0; i < users.length; i++) {
        for (j = 0; j < challs.length; j++) {
            var c = users[i].challenges[challs[j]];
            if (c.timestamp !== null) {
                submissions.push({ challenge: challs[j], date: new Date(c.timestamp) });
            }
        }
    }
    submissions.sort(compareByDate);

    /* Create a graph for each challenge that displays the number of solvers at each time. */
    var solvers = {};
    for (i = 0; i < challs.length; i++) {
        var g = $.extend(true, {}, defaultGraphSettings);
        g.balloonText = "[[title]] solved by [[value]]";
        g.title = g.valueField = challs[i];
        chart.graphs.push(g);
        solvers[challs[i]] = 0;
    }
    for (i = 0; i < submissions.length; i++) {
        var cn = submissions[i].challenge;
        s = { date: submissions[i].date };
        solvers[cn]++;
        s[cn] = solvers[cn];
        chart.dataProvider.push(s);
    }

    /* For each user, add a fake point in the corresponding graph dated as the last submission.
     * In this way all graphs span the entire chart area. */
    var lastSubmission = chart.dataProvider[chart.dataProvider.length - 1].date;
    for (i = 0; i < challs.length; i++) {
        s = { date: lastSubmission };
        s[challs[i]] = solvers[challs[i]];
        chart.dataProvider.push(s);
    }
}