var defaultGraphSettings = {
    "lineThickness": 3,
    "type": "line"
};

var defaultChartSettings = {
    "categoryAxis": {
        "minPeriod": "ss",
        "parseDates": false,
        "title": "Round"
    },
    "categoryField": "round",
    "chartCursor": {
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
        "text": "Global Score"
    }],
    "type": "serial",
    "valueAxes": [{
        "title": "Points"
    }],
    "numberFormatter": {
        "precision": 2,
        "decimalSeparator": ".",
        "thousandsSeparator": ""
    }
};

function makeChart(divId, data, populate) {
    var chart = $.extend(true, {}, defaultChartSettings);
    populate(chart, data);
    AmCharts.makeChart(divId, chart);
}

function compareByDate(o1, o2) {
    return o1.date - o2.date;
}

function scoresChart(chart, scores) {
    chart.graphs = [];
    chart.dataProvider = [];

    for (var team in scores) {
        var g = $.extend(true, {}, defaultGraphSettings);
        g.balloonText = "[[title]]\n[[value]]pts";
        g.title = g.valueField = team;
        chart.graphs.push(g);
        for (round in scores[team]) {
            var s = { round: round | 0 };
            s[g.valueField] = scores[team][round];
            chart.dataProvider.push(s);
        }
        chart.dataProvider.sort(function (a,b) { return a.round - b.round; });
    }
}
