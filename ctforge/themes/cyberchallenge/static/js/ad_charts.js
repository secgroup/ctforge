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

function teamsChart(chart, teams) {
    chart.titles[0].text = "Global Score (top 10)";
    chart.valueAxes[0].title = "Points";
    chart.graphs = [];
    chart.dataProvider = [];

    if (teams.length === 0) return;

}
