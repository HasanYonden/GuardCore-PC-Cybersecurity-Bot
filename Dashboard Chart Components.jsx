import React, { useRef, useEffect } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, RadialLinearScale, Title } from 'chart.js';
import { Doughnut, Line, Bar, PolarArea } from 'react-chartjs-2';
import { useTheme } from '../contexts/ThemeContext';

// Register ChartJS components
ChartJS.register(
  ArcElement, 
  Tooltip, 
  Legend, 
  CategoryScale, 
  LinearScale, 
  PointElement, 
  LineElement, 
  BarElement,
  RadialLinearScale,
  Title
);

// Security Score Chart (Doughnut)
export const SecurityScoreChart = ({ score }) => {
  const { isDark } = useTheme();
  const chartRef = useRef(null);
  
  // Update gradient on theme change
  useEffect(() => {
    if (chartRef.current) {
      const ctx = chartRef.current.ctx;
      const chart = chartRef.current;
      
      // Create gradient for the score segment
      const scoreGradient = ctx.createLinearGradient(0, 0, 0, 400);
      
      if (score >= 80) {
        // Good score - green gradient
        scoreGradient.addColorStop(0, isDark ? '#059669' : '#10b981');
        scoreGradient.addColorStop(1, isDark ? '#065f46' : '#34d399');
      } else if (score >= 50) {
        // Medium score - yellow gradient
        scoreGradient.addColorStop(0, isDark ? '#d97706' : '#f59e0b');
        scoreGradient.addColorStop(1, isDark ? '#92400e' : '#fbbf24');
      } else {
        // Poor score - red gradient
        scoreGradient.addColorStop(0, isDark ? '#b91c1c' : '#ef4444');
        scoreGradient.addColorStop(1, isDark ? '#7f1d1d' : '#f87171');
      }
      
      // Set the gradient in the dataset
      if (chart && chart.data && chart.data.datasets && chart.data.datasets[0]) {
        chart.data.datasets[0].backgroundColor = [
          scoreGradient,
          isDark ? '#374151' : '#e5e7eb'
        ];
        chart.update();
      }
    }
  }, [score, isDark]);
  
  const data = {
    labels: ['Secure', 'Needs Attention'],
    datasets: [
      {
        data: [score, 100 - score],
        backgroundColor: [
          // Will be set by the useEffect
          '#10b981',
          isDark ? '#374151' : '#e5e7eb'
        ],
        borderWidth: 0,
        borderRadius: 10,
      },
    ],
  };
  
  const options = {
    responsive: true,
    cutout: '78%',
    plugins: {
      legend: {
        display: false
      },
      tooltip: {
        enabled: false
      }
    },
    rotation: 270, // Start from top
    circumference: 180, // Half circle
    maintainAspectRatio: false
  };
  
  return (
    <div className="relative h-40">
      <Doughnut ref={chartRef} data={data} options={options} />
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="text-center">
          <span className="text-2xl font-bold">{score}</span>
          <span className="text-sm ml-1 text-gray-500 dark:text-gray-400">/100</span>
        </div>
      </div>
    </div>
  );
};

// Threats Over Time Chart (Line)
export const ThreatsOverTimeChart = ({ data }) => {
  const { isDark } = useTheme();
  
  const chartData = {
    labels: data.map(d => d.month),
    datasets: [
      {
        label: 'Detected',
        data: data.map(d => d.detected),
        borderColor: isDark ? '#3b82f6' : '#2563eb',
        backgroundColor: 'rgba(59, 130, 246, 0.5)',
        tension: 0.2,
      },
      {
        label: 'Blocked',
        data: data.map(d => d.blocked),
        borderColor: isDark ? '#10b981' : '#059669',
        backgroundColor: 'rgba(16, 185, 129, 0.5)',
        tension: 0.2,
      }
    ],
  };
  
  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: isDark ? '#d1d5db' : '#4b5563',
          padding: 10,
          usePointStyle: true,
          pointStyle: 'circle'
        }
      },
      title: {
        display: false
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      }
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: isDark ? 'rgba(75, 85, 99, 0.2)' : 'rgba(209, 213, 219, 0.5)',
        },
        ticks: {
          color: isDark ? '#d1d5db' : '#4b5563',
          precision: 0
        }
      },
      x: {
        grid: {
          display: false
        },
        ticks: {
          color: isDark ? '#d1d5db' : '#4b5563'
        }
      }
    },
    maintainAspectRatio: false
  };
  
  return (
    <div className="h-80">
      <Line data={chartData} options={options} />
    </div>
  );
};

// Resource Usage Chart (Bar)
export const ResourceUsageChart = ({ data }) => {
  const { isDark } = useTheme();
  
  const chartData = {
    labels: ['CPU', 'Memory', 'Disk I/O', 'Network'],
    datasets: [
      {
        label: 'System Usage',
        data: [
          data.cpu.system,
          data.memory.system,
          data.disk.system,
          data.network.system
        ],
        backgroundColor: isDark ? 'rgba(107, 114, 128, 0.8)' : 'rgba(107, 114, 128, 0.5)',
      },
      {
        label: 'GuardCore Usage',
        data: [
          data.cpu.guardcore,
          data.memory.guardcore,
          data.disk.guardcore,
          data.network.guardcore
        ],
        backgroundColor: isDark ? 'rgba(59, 130, 246, 0.8)' : 'rgba(59, 130, 246, 0.5)',
      }
    ],
  };
  
  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: isDark ? '#d1d5db' : '#4b5563',
          padding: 10,
          usePointStyle: true,
          pointStyle: 'circle'
        }
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        grid: {
          color: isDark ? 'rgba(75, 85, 99, 0.2)' : 'rgba(209, 213, 219, 0.5)',
        },
        ticks: {
          color: isDark ? '#d1d5db' : '#4b5563',
          callback: function(value) {
            return value + '%';
          }
        }
      },
      x: {
        grid: {
          display: false
        },
        ticks: {
          color: isDark ? '#d1d5db' : '#4b5563'
        }
      }
    },
    maintainAspectRatio: false
  };
  
  return (
    <div className="h-72">
      <Bar data={chartData} options={options} />
    </div>
  );
};

// Threat Types Chart (Polar Area)
export const ThreatTypesChart = ({ data }) => {
  const { isDark } = useTheme();
  
  const chartData = {
    labels: data.map(d => d.type),
    datasets: [
      {
        data: data.map(d => d.count),
        backgroundColor: [
          'rgba(239, 68, 68, 0.7)',   // Red
          'rgba(245, 158, 11, 0.7)',  // Amber
          'rgba(59, 130, 246, 0.7)',  // Blue
          'rgba(16, 185, 129, 0.7)',  // Green
          'rgba(139, 92, 246, 0.7)',  // Purple
        ],
        borderWidth: 1,
        borderColor: isDark ? '#1f2937' : '#f3f4f6'
      },
    ],
  };
  
  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: isDark ? '#d1d5db' : '#4b5563',
          padding: 15,
          usePointStyle: true,
          pointStyle: 'circle'
        }
      },
    },
    scales: {
      r: {
        ticks: {
          display: false,
          backdropColor: 'transparent'
        },
        grid: {
          color: isDark ? 'rgba(75, 85, 99, 0.2)' : 'rgba(209, 213, 219, 0.5)',
        },
        angleLines: {
          color: isDark ? 'rgba(75, 85, 99, 0.2)' : 'rgba(209, 213, 219, 0.5)',
        },
      }
    },
    maintainAspectRatio: false
  };
  
  return (
    <div className="h-80">
      <PolarArea data={chartData} options={options} />
    </div>
  );
};

// Small Sparkline Chart
export const SparklineChart = ({ data, color, height = 40, showArea = true }) => {
  const { isDark } = useTheme();
  
  const baseColor = color || (isDark ? '#3b82f6' : '#2563eb');
  
  const chartData = {
    labels: new Array(data.length).fill(''),
    datasets: [
      {
        data: data,
        borderColor: baseColor,
        backgroundColor: showArea ? `${baseColor}25` : 'transparent',
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 3,
        tension: 0.3,
        fill: showArea
      },
    ],
  };
  
  const options = {
    responsive: true,
    plugins: {
      legend: {
        display: false
      },
      tooltip: {
        enabled: false
      }
    },
    scales: {
      y: {
        display: false,
        beginAtZero: false
      },
      x: {
        display: false
      }
    },
    maintainAspectRatio: false,
    elements: {
      line: {
        tension: 0.3
      }
    }
  };
  
  return (
    <div style={{ height: `${height}px` }}>
      <Line data={chartData} options={options} />
    </div>
  );
};

// Usage:
// <SecurityScoreChart score={85} />
// <ThreatsOverTimeChart data={[
//   { month: 'Jan', detected: 12, blocked: 10 },
//   { month: 'Feb', detected: 8, blocked: 8 },
//   { month: 'Mar', detected: 15, blocked: 14 },
//   /* ... */
// ]} />
// <ResourceUsageChart data={{
//   cpu: { system: 25, guardcore: 5 },
//   memory: { system: 45, guardcore: 12 },
//   disk: { system: 15, guardcore: 3 },
//   network: { system: 10, guardcore: 2 }
// }} />
// <ThreatTypesChart data={[
//   { type: 'Malware', count: 12 },
//   { type: 'Phishing', count: 5 },
//   { type: 'Intrusion', count: 8 },
//   { type: 'PUA', count: 3 },
//   { type: 'Other', count: 2 }
// ]} />
// <SparklineChart data={[5, 8, 3, 7, 9, 4, 6, 8]} color="#3b82f6" height={40} />