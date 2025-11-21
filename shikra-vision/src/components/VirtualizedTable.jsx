import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { FixedSizeList as List } from 'react-window';

// Virtual scrolling for handling 1000+ records efficiently
const VirtualizedTable = ({ 
  data, 
  columns, 
  rowHeight = 60, 
  maxHeight = 400, 
  onRowClick, 
  selectedIds = new Set()
}) => {
  const [sortedData, setSortedData] = useState(data);
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  const handleSort = useCallback((key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    
    const sorted = [...data].sort((a, b) => {
      if (a[key] < b[key]) return direction === 'asc' ? -1 : 1;
      if (a[key] > b[key]) return direction === 'asc' ? 1 : -1;
      return 0;
    });
    
    setSortedData(sorted);
    setSortConfig({ key, direction });
  }, [data, sortConfig]);

  const Row = ({ index, style }) => {
    const item = sortedData[index];
    const isSelected = selectedIds.has(item.id);
    
    return (
      <div 
        style={style}
        className={`flex items-center border-b border-gray-200 dark:border-gray-700 cursor-pointer transition-colors ${
          isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-gray-50 dark:hover:bg-gray-700'
        }`}
        onClick={() => onRowClick?.(item)}
      >
        {columns.map((column, colIndex) => (
          <div
            key={colIndex}
            className={`px-4 py-2 ${column.className || ''}`}
            style={{ width: column.width, minWidth: column.minWidth }}
          >
            {column.render ? column.render(item) : item[column.key]}
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gray-50 dark:bg-gray-700 flex border-b border-gray-200 dark:border-gray-600">
        {columns.map((column, index) => (
          <div
            key={index}
            className={`px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600 ${column.className || ''}`}
            style={{ width: column.width, minWidth: column.minWidth }}
            onClick={() => column.sortable && handleSort(column.key)}
          >
            <div className="flex items-center">
              {column.title}
              {column.sortable && sortConfig.key === column.key && (
                <span className="ml-1">
                  {sortConfig.direction === 'asc' ? '↑' : '↓'}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
      
      {/* Virtual List */}
      <List
        height={Math.min(maxHeight, sortedData.length * rowHeight)}
        itemCount={sortedData.length}
        itemSize={rowHeight}
        itemData={sortedData}
      >
        {Row}
      </List>
    </div>
  );
};

export default VirtualizedTable;
