
/* CTForge: Forge your own CTF.
   
 * 
 * Copyright (C) 2016-2019  Marco Squarcina
 * Copyright (C) 2016-2019  Mauro Tempesta
 * Copyright (C) 2016-2019  Lorenzo Veronese
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>. */
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

var adChart = null;

function makeChart(divId, data, populate) {
    if (adChart) adChart.clear();
    adChart = $.extend(true, {}, defaultChartSettings);
    populate(adChart, data);
    AmCharts.makeChart(divId, adChart);
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
