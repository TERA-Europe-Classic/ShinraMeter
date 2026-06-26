using Data;
using Data.Actions.Notify.SoundElements;
using Data.Events;
using Data.Events.Abnormality;
using Nostrum;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Tera.Game;

namespace DamageMeter.UI
{
    public enum SoundType
    {
        None,
        Beeps,
        Music,
        TTS
    }

    public class EventsEditorViewModel : TSPropertyChanged
    {
        public static IEnumerable<PlayerClass> Classes = EnumUtils.ListFromEnum<PlayerClass>();
        public static IEnumerable<EventType> EventTypes = EnumUtils.ListFromEnum<EventType>();
        public static IEnumerable<SoundType> SoundTypes = EnumUtils.ListFromEnum<SoundType>();

        public static IEnumerable<VoiceGender> Genders
        {
            get
            {
                var ret = EnumUtils.ListFromEnum<VoiceGender>();
                ret.Remove(VoiceGender.NotSet);
                return ret;

            }
        }


        public static IEnumerable<VoiceAge> Ages
        {
            get
            {
                var ret = EnumUtils.ListFromEnum<VoiceAge>();
                ret.Remove(VoiceAge.NotSet);
                return ret;

            }
        }

        public static IEnumerable<AbnormalityTargetType> TargetTypes = EnumUtils.ListFromEnum<AbnormalityTargetType>();
        public static IEnumerable<AbnormalityTriggerType> TriggerTypes = EnumUtils.ListFromEnum<AbnormalityTriggerType>();

        public static Color SelfColor => BasicTeraData.Instance.WindowData.PlayerColor;

        private readonly EventsData _data;
        private string _searchText;
        private bool _showActiveOnly;

        public ICommand LoadCommand { get; }
        public ICommand ApplyCommand { get; }

        public SynchronizedObservableCollection<BaseEventViewModel> CommonEvents { get; }
        public ICollectionView EventsView { get; }

        public string SearchText
        {
            get => _searchText;
            set
            {
                if (_searchText == value) return;
                _searchText = value;
                NotifyPropertyChanged();
                EventsView.Refresh();
            }
        }

        public bool ShowActiveOnly
        {
            get => _showActiveOnly;
            set
            {
                if (_showActiveOnly == value) return;
                _showActiveOnly = value;
                NotifyPropertyChanged();
                EventsView.Refresh();
            }
        }

        public EventsEditorViewModel()
        {
            _data = BasicTeraData.Instance.EventsData;

            CommonEvents = new SynchronizedObservableCollection<BaseEventViewModel>();
            EventsView = CollectionViewSource.GetDefaultView(CommonEvents);
            EventsView.Filter = FilterEvent;

            LoadCommand = new RelayCommand(_ => Load());
            ApplyCommand = new RelayCommand(_ => Apply());

            Load();
        }

        private void Apply()
        {
            _data.Save();
        }

        private void Load()
        {
            CommonEvents.Clear();

            // load data from model
            foreach (var (commonEvent, actions) in _data.EventsCommon)
            {
                AddEvent(commonEvent switch
                {
                    AbnormalityEvent ab => new AbnormalityEventViewModel(ab, actions),
                    CooldownEvent cd => new CooldownEventViewModel(cd, actions),
                    CommonAFKEvent afk => new AfkEventViewModel(afk, actions),
                    _ => throw new ArgumentOutOfRangeException()
                });
            }
        }

        private void AddEvent(BaseEventViewModel ev)
        {
            ev.PropertyChanged += (_, args) =>
            {
                if (args.PropertyName == nameof(BaseEventViewModel.Active) || args.PropertyName == nameof(BaseEventViewModel.SearchText))
                {
                    EventsView.Refresh();
                }
            };
            CommonEvents.Add(ev);
        }

        private bool FilterEvent(object item)
        {
            if (item is not BaseEventViewModel ev) return false;
            if (ShowActiveOnly && !ev.Active) return false;
            if (string.IsNullOrWhiteSpace(SearchText)) return true;
            return CultureInfo.InvariantCulture.CompareInfo.IndexOf(
                ev.SearchText ?? string.Empty,
                SearchText,
                CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) >= 0;
        }
    }

    public class SoundTemplateSelector : DataTemplateSelector
    {
        public DataTemplate MusicDataTemplate { get; set; }
        public DataTemplate BeepsDataTemplate { get; set; }
        public DataTemplate TtsDataTemplate { get; set; }

        public override DataTemplate SelectTemplate(object item, DependencyObject container)
        {
            return item switch
            {
                MusicDataVM => MusicDataTemplate,
                BeepsDataVM => BeepsDataTemplate,
                TtsDataVM => TtsDataTemplate,
                _ => null
            };
        }
    }

    public class EventTemplateSelector : DataTemplateSelector
    {
        public DataTemplate AbnormalityDataTemplate { get; set; }
        public DataTemplate CooldownDataTemplate { get; set; }
        public DataTemplate AfkDataTemplate { get; set; }

        public override DataTemplate SelectTemplate(object item, DependencyObject container)
        {
            return item switch
            {
                AbnormalityEventViewModel => AbnormalityDataTemplate,
                CooldownEventViewModel => CooldownDataTemplate,
                AfkEventViewModel => AfkDataTemplate,
                _ => null
            };
        }
    }
}
