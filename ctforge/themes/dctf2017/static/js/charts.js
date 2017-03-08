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
        "enabled": true
    },
    "dataDateFormat": "YYYY-MM-DD HH:NN:SS",
    "fontFamily": "Monda",
    "fontSize": 14,
    "legend": {
        "color": "#D4D4D4",
        "enabled": true,
        "useGraphSettings": true
    },
    "startDuration": 0.5,
    "startEffect": "easeOutSine",
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
    populate(chart, data)
    AmCharts.makeChart(divId, chart);
}

function compareByDate(o1, o2) {
    return o1.date - o2.date;
}

function usersChart(chart, users) {
    chart.titles[0].text = "Players";
    chart.valueAxes[0].title = "Points";
    chart.graphs = [];
    chart.dataProvider = [];

    if (users.length === 0) return;

    var i, j, s;
    var challs = Object.keys(users[0].challenges);
    for (i = 0; i < users.length; i++) {
        /* Create a new graph for the user. */
        var g = $.extend(true, {}, defaultGraphSettings);
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

    console.log(submissions);

    /* Create a graph for each challenge that displays the number of solvers at each time. */
    var solvers = {};
    for (i = 0; i < challs.length; i++) {
        var g = $.extend(true, {}, defaultGraphSettings);
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

    console.log(chart.dataProvider);

    /* For each user, add a fake point in the corresponding graph dated as the last submission.
     * In this way all graphs span the entire chart area. */
    var lastSubmission = chart.dataProvider[chart.dataProvider.length - 1].date;
    for (i = 0; i < challs.length; i++) {
        s = { date: lastSubmission };
        s[challs[i]] = solvers[challs[i]];
        chart.dataProvider.push(s);
    }
}

// "dataProvider": [
//       {
//         "column-0": 1,
//         "date": "2017-02-14 17:48:09"
//       },
//       {
//         "column-0": 2,
//         "date": "2017-02-14 18:38:24"
//       },
//       {
//         "column-0": 3,
//         "date": "2017-02-14 19:30:14"
//       },
//       {
//         "column-0": 4,
//         "date": "2017-02-14 20:26:09"
//       },
//       {
//         "column-0": 5,
//         "date": "2017-02-14 21:11:55"
//       },
//       {
//         "column-0": 6,
//         "date": "2017-02-14 22:23:20"
//       },
//       {
//         "column-0": 7,
//         "date": "2017-02-15 08:38:46"
//       },
//       {
//         "column-0": 8,
//         "date": "2017-02-15 08:44:43"
//       },
//       {
//         "column-0": 9,
//         "date": "2017-02-15 08:49:18"
//       },
//       {
//         "column-0": 10,
//         "date": "2017-02-15 10:35:21"
//       },
//       {
//         "column-0": 11,
//         "date": "2017-02-15 20:29:11"
//       },
//       {
//         "column-0": 12,
//         "date": "2017-02-16 12:48:50"
//       },
//       {
//         "column-0": 13,
//         "date": "2017-02-16 14:14:55"
//       },
//       {
//         "column-0": 14,
//         "date": "2017-02-17 08:44:15"
//       },
//       {
//         "column-0": 15,
//         "date": "2017-02-17 22:28:08"
//       },
//       {
//         "column-0": 16,
//         "date": "2017-02-18 02:05:30"
//       },
//       {
//         "column-0": 17,
//         "date": "2017-02-20 11:53:18"
//       },
//       {
//         "column-0": 18,
//         "date": "2017-02-23 01:34:05"
//       },
//       {
//         "column-0": 18,
//         "date": "2017-03-08 15:58:04"
//       },
//       {
//         "column-1": 1,
//         "date": "2017-02-17 10:09:11"
//       },
//       {
//         "column-1": 2,
//         "date": "2017-02-17 11:55:34"
//       },
//       {
//         "column-1": 3,
//         "date": "2017-02-17 14:09:09"
//       },
//       {
//         "column-1": 4,
//         "date": "2017-02-17 14:58:17"
//       },
//       {
//         "column-1": 5,
//         "date": "2017-02-17 15:31:26"
//       },
//       {
//         "column-1": 6,
//         "date": "2017-02-17 16:16:39"
//       },
//       {
//         "column-1": 7,
//         "date": "2017-02-17 17:27:07"
//       },
//       {
//         "column-1": 8,
//         "date": "2017-02-18 01:28:01"
//       },
//       {
//         "column-1": 9,
//         "date": "2017-02-18 08:46:36"
//       },
//       {
//         "column-1": 10,
//         "date": "2017-02-18 10:05:23"
//       },
//       {
//         "column-1": 11,
//         "date": "2017-02-18 14:10:16"
//       },
//       {
//         "column-1": 12,
//         "date": "2017-02-18 20:22:42"
//       },
//       {
//         "column-1": 13,
//         "date": "2017-02-19 00:07:37"
//       },
//       {
//         "column-1": 14,
//         "date": "2017-02-19 21:21:05"
//       },
//       {
//         "column-1": 15,
//         "date": "2017-02-19 22:21:53"
//       },
//       {
//         "column-1": 16,
//         "date": "2017-02-21 22:31:00"
//       },
//       {
//         "column-1": 16,
//         "date": "2017-03-08 15:58:04"
//       },
//       {
//         "column-2": 1,
//         "date": "2017-02-22 10:17:04"
//       },
//       {
//         "column-2": 2,
//         "date": "2017-02-22 11:20:58"
//       },
//       {
//         "column-2": 3,
//         "date": "2017-02-22 11:21:11"
//       },
//       {
//         "column-2": 4,
//         "date": "2017-02-22 11:52:26"
//       },
//       {
//         "column-2": 5,
//         "date": "2017-02-22 11:58:54"
//       },
//       {
//         "column-2": 6,
//         "date": "2017-02-22 12:05:12"
//       },
//       {
//         "column-2": 7,
//         "date": "2017-02-22 12:06:14"
//       },
//       {
//         "column-2": 8,
//         "date": "2017-02-22 14:07:09"
//       },
//       {
//         "column-2": 9,
//         "date": "2017-02-22 19:27:31"
//       },
//       {
//         "column-2": 10,
//         "date": "2017-02-22 20:34:14"
//       },
//       {
//         "column-2": 10,
//         "date": "2017-03-08 15:58:04"
//       }
//     ]

// "graphs": [
//       {
//         "balloonText": "[[title]] solved by [[value]]",
//         "id": "mygraph-0",
//         "lineThickness": 3,
//         "title": "agreement",
//         "type": "line",
//         "valueField": "column-0"
//       },
//       {
//         "balloonText": "[[title]] solved by [[value]]",
//         "id": "mygraph-1",
//         "lineThickness": 3,
//         "title": "alienquiz",
//         "type": "line",
//         "valueField": "column-1"
//       },
//       {
//         "balloonText": "[[title]] solved by [[value]]",
//         "id": "mygraph-2",
//         "lineThickness": 3,
//         "title": "vadermail",
//         "type": "line",
//         "valueField": "column-2"
//       }
//     ],